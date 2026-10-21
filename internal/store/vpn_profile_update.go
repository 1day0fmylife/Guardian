package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

const (
	DefaultProfileRotationGrace = 7 * 24 * time.Hour
	MaxProfileRotationGrace     = 90 * 24 * time.Hour
	profileApplyCommandTTL      = 24 * time.Hour
)

// VPNProfileUpdate changes a profile in place. Nil fields keep their value.
// The address pool is immutable: moving devices to another pool is a
// re-addressing, not a profile edit.
type VPNProfileUpdate struct {
	ExpectedRevision    int64
	Name                *string
	ServerPublicKey     *string
	Endpoint            *string
	AllowedIPs          *[]string
	DNSServers          *[]string
	PersistentKeepalive *int
	AddressPoolID       *string
	// RotationGrace is how long the replaced server key/endpoint stay listed
	// as previous_* (zero: DefaultProfileRotationGrace).
	RotationGrace time.Duration
}

type VPNProfileUpdateResult struct {
	Profile domain.VPNProfile
	// Changed is false for a request that matches the stored profile, so a
	// retried PUT after a lost response is answered without a new revision.
	Changed bool
	// DeviceConfigChanged is true when devices must apply a new configuration.
	DeviceConfigChanged bool
	ServerKeyRotated    bool
	AffectedPeers       int
	// NotifiedDeviceIDs received an apply-config command in this update.
	NotifiedDeviceIDs []string
}

// UpdateVPNProfile applies a profile change and, in the same transaction,
// raises the config revision of every peer of the profile and queues an
// apply-config command for every active device. Devices fetch the new
// configuration over the management channel, which does not depend on the
// tunnel, so changing the server key or endpoint never requires re-enrollment.
func (s *Store) UpdateVPNProfile(ctx context.Context, meta AuditMeta, id string, input VPNProfileUpdate) (VPNProfileUpdateResult, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return VPNProfileUpdateResult{}, ErrNotFound
	}
	if input.RotationGrace == 0 {
		input.RotationGrace = DefaultProfileRotationGrace
	}
	if input.RotationGrace < 0 || input.RotationGrace > MaxProfileRotationGrace {
		return VPNProfileUpdateResult{}, catalogErr(ErrInvalid, "invalid_rotation_grace", "rotation grace must be between 0 and 90 days")
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return VPNProfileUpdateResult{}, fmt.Errorf("begin VPN profile update: %w", err)
	}
	defer tx.Rollback()

	// SQLite serializes writers on the first write; take it before reading so
	// the revision check and the peer bump see one consistent profile.
	if s.dialect != "postgres" {
		if _, err := tx.ExecContext(ctx, s.q("UPDATE vpn_profiles SET revision = revision WHERE id = ?"), id); err != nil {
			return VPNProfileUpdateResult{}, fmt.Errorf("lock VPN profile: %w", err)
		}
	}
	query := "SELECT " + vpnProfileColumns + " FROM vpn_profiles WHERE id = ?"
	if s.dialect == "postgres" {
		query += " FOR UPDATE"
	}
	current, err := scanVPNProfile(tx.QueryRowContext(ctx, s.q(query), id).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VPNProfileUpdateResult{}, ErrNotFound
		}
		return VPNProfileUpdateResult{}, fmt.Errorf("load VPN profile: %w", err)
	}

	next := current
	if input.Name != nil {
		next.Name = strings.TrimSpace(*input.Name)
		if next.Name == "" || len(next.Name) > 200 {
			return VPNProfileUpdateResult{}, catalogErr(ErrInvalid, "invalid_profile", "profile name is invalid")
		}
	}
	if input.AddressPoolID != nil && strings.TrimSpace(*input.AddressPoolID) != current.AddressPoolID {
		return VPNProfileUpdateResult{}, catalogErr(ErrConflict, "profile_address_pool_immutable", "the address pool of a profile cannot be changed")
	}
	fields := vpnProfileFields{
		ServerPublicKey: current.ServerPublicKey, Endpoint: current.Endpoint, AllowedIPs: current.AllowedIPs,
		DNSServers: current.DNSServers, PersistentKeepalive: current.PersistentKeepalive,
	}
	if input.ServerPublicKey != nil {
		fields.ServerPublicKey = *input.ServerPublicKey
	}
	if input.Endpoint != nil {
		fields.Endpoint = *input.Endpoint
	}
	if input.AllowedIPs != nil {
		fields.AllowedIPs = *input.AllowedIPs
	}
	if input.DNSServers != nil {
		fields.DNSServers = *input.DNSServers
	}
	if input.PersistentKeepalive != nil {
		fields.PersistentKeepalive = *input.PersistentKeepalive
	}
	if err := fields.normalize(); err != nil {
		if errors.Is(err, security.ErrInvalidWireGuardPublicKey) {
			return VPNProfileUpdateResult{}, err
		}
		return VPNProfileUpdateResult{}, catalogErr(ErrInvalid, "invalid_profile", strings.TrimPrefix(err.Error(), ErrInvalid.Error()+": "))
	}
	next.ServerPublicKey, next.Endpoint = fields.ServerPublicKey, fields.Endpoint
	next.AllowedIPs, next.DNSServers, next.PersistentKeepalive = fields.AllowedIPs, fields.DNSServers, fields.PersistentKeepalive

	keyRotated := next.ServerPublicKey != current.ServerPublicKey
	endpointChanged := next.Endpoint != current.Endpoint
	configChanged := keyRotated || endpointChanged ||
		!slices.Equal(next.AllowedIPs, current.AllowedIPs) ||
		!slices.Equal(next.DNSServers, current.DNSServers) ||
		next.PersistentKeepalive != current.PersistentKeepalive
	if !configChanged && next.Name == current.Name {
		// Identical request: idempotent replay, whatever expected_revision says.
		return VPNProfileUpdateResult{Profile: current}, nil
	}
	if input.ExpectedRevision != current.Revision {
		return VPNProfileUpdateResult{}, catalogErr(ErrConflict, "revision_conflict", "the profile was changed by someone else; reload it")
	}

	if next.Name != current.Name {
		var taken int
		if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM vpn_profiles WHERE name = ? AND id <> ?"), next.Name, id).Scan(&taken); err != nil {
			return VPNProfileUpdateResult{}, fmt.Errorf("check VPN profile name: %w", err)
		}
		if taken != 0 {
			return VPNProfileUpdateResult{}, catalogErr(ErrConflict, "profile_name_taken", "another profile has this name")
		}
	}

	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339Nano)
	next.Revision = current.Revision + 1
	next.UpdatedAt = nowStr
	if keyRotated || endpointChanged {
		next.PreviousServerPublicKey = current.ServerPublicKey
		next.PreviousEndpoint = current.Endpoint
		next.PreviousValidUntil = now.Add(input.RotationGrace).Format(time.RFC3339Nano)
	}
	var validUntil any
	if next.PreviousValidUntil != "" {
		validUntil = next.PreviousValidUntil
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		UPDATE vpn_profiles
		SET name = ?, server_public_key = ?, endpoint = ?, allowed_ips = ?, dns_servers = ?,
		    persistent_keepalive = ?, revision = ?, previous_server_public_key = ?,
		    previous_endpoint = ?, previous_valid_until = ?, updated_at = ?
		WHERE id = ? AND revision = ?
	`), next.Name, next.ServerPublicKey, next.Endpoint, strings.Join(next.AllowedIPs, ","),
		strings.Join(next.DNSServers, ","), next.PersistentKeepalive, next.Revision,
		next.PreviousServerPublicKey, next.PreviousEndpoint, validUntil, nowStr, id, current.Revision); err != nil {
		return VPNProfileUpdateResult{}, fmt.Errorf("update VPN profile: %w", err)
	}

	result := VPNProfileUpdateResult{Profile: next, Changed: true, DeviceConfigChanged: configChanged, ServerKeyRotated: keyRotated}
	if configChanged {
		if err := s.rollOutProfileTx(ctx, tx, next, now, &result); err != nil {
			return VPNProfileUpdateResult{}, err
		}
	}
	details := map[string]any{
		"revision":             next.Revision,
		"server_key_rotated":   keyRotated,
		"endpoint_changed":     endpointChanged,
		"device_config":        configChanged,
		"affected_peers":       result.AffectedPeers,
		"notified_devices":     len(result.NotifiedDeviceIDs),
		"server_public_key":    next.ServerPublicKey,
		"previous_valid_until": next.PreviousValidUntil,
	}
	if keyRotated {
		details["previous_server_public_key"] = current.ServerPublicKey
	}
	if err := s.appendAuditTx(ctx, tx, meta, "vpn_profile.update", "vpn_profile", id, details); err != nil {
		return VPNProfileUpdateResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return VPNProfileUpdateResult{}, fmt.Errorf("commit VPN profile update: %w", err)
	}
	return result, nil
}

// rollOutProfileTx bumps every peer of the profile to a new config revision
// and queues apply-config for active devices. Suspended devices keep their
// disconnected desired state and pick the new values up on resume.
func (s *Store) rollOutProfileTx(ctx context.Context, tx *sql.Tx, profile domain.VPNProfile, now time.Time, result *VPNProfileUpdateResult) error {
	query := `
		SELECT p.id, p.device_id, p.config_revision, d.status, d.suspended
		FROM wireguard_peers p
		JOIN devices d ON d.id = p.device_id
		WHERE p.profile_id = ? AND p.revoked_at IS NULL
		ORDER BY p.id
	`
	if s.dialect == "postgres" {
		query += " FOR UPDATE OF p"
	}
	rows, err := tx.QueryContext(ctx, s.q(query), profile.ID)
	if err != nil {
		return fmt.Errorf("list profile peers: %w", err)
	}
	type peer struct {
		id, deviceID, status string
		revision             int64
		suspended            int
	}
	var peers []peer
	for rows.Next() {
		var p peer
		if err := rows.Scan(&p.id, &p.deviceID, &p.revision, &p.status, &p.suspended); err != nil {
			rows.Close()
			return fmt.Errorf("scan profile peer: %w", err)
		}
		peers = append(peers, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate profile peers: %w", err)
	}
	rows.Close()

	nowStr := now.Format(time.RFC3339Nano)
	expires := now.Add(profileApplyCommandTTL).Format(time.RFC3339Nano)
	payload := fmt.Sprintf(`{"reason":"profile_updated","profile_id":%q,"profile_revision":%d}`, profile.ID, profile.Revision)
	for _, p := range peers {
		if _, err := tx.ExecContext(ctx, s.q(`
			UPDATE wireguard_peers
			SET config_revision = ?, reconcile_state = 'pending', reconcile_error = '', updated_at = ?
			WHERE id = ? AND config_revision = ?
		`), p.revision+1, nowStr, p.id, p.revision); err != nil {
			return fmt.Errorf("bump peer config revision: %w", err)
		}
		result.AffectedPeers++
		if p.status != "active" || p.suspended != 0 {
			continue
		}
		commandID, err := security.NewID()
		if err != nil {
			return err
		}
		key := fmt.Sprintf("profile:%s:r%d:%s", profile.ID, profile.Revision, p.id)
		if _, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO device_commands(id, device_id, type, status, idempotency_key, payload, result, created_at, expires_at)
			VALUES(?, ?, 'apply-config', 'pending', ?, ?, '{}', ?, ?)
		`), commandID, p.deviceID, key, payload, nowStr, expires); err != nil {
			return fmt.Errorf("queue profile apply-config: %w", err)
		}
		result.NotifiedDeviceIDs = append(result.NotifiedDeviceIDs, p.deviceID)
	}
	return nil
}

// VPNProfileRollout reports how many devices run the current configuration
// of a profile, judged by the config revision in their latest telemetry.
type VPNProfileRollout struct {
	ProfileID          string   `json:"profile_id"`
	Revision           int64    `json:"revision"`
	Peers              int      `json:"peers"`
	Applied            int      `json:"applied"`
	Pending            int      `json:"pending"`
	PendingDeviceIDs   []string `json:"pending_device_ids"`
	PreviousValidUntil string   `json:"previous_valid_until,omitempty"`
	// PreviousKeyRetirable is true when no device still needs the previous
	// server key: all have applied, or the grace period is over.
	PreviousKeyRetirable bool `json:"previous_key_retirable"`
}

func (s *Store) VPNProfileRollout(ctx context.Context, id string, limit int) (VPNProfileRollout, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	profile, err := s.GetVPNProfile(ctx, id)
	if err != nil {
		return VPNProfileRollout{}, err
	}
	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT p.device_id, p.config_revision,
		       COALESCE((SELECT t.config_revision FROM device_telemetry t
		                 WHERE t.device_id = p.device_id
		                 ORDER BY t.observed_at DESC LIMIT 1), 0)
		FROM wireguard_peers p
		JOIN devices d ON d.id = p.device_id
		WHERE p.profile_id = ? AND p.revoked_at IS NULL AND d.status = 'active' AND d.suspended = 0
		ORDER BY p.device_id
	`), id)
	if err != nil {
		return VPNProfileRollout{}, fmt.Errorf("load profile rollout: %w", err)
	}
	defer rows.Close()
	out := VPNProfileRollout{ProfileID: id, Revision: profile.Revision, PendingDeviceIDs: []string{}, PreviousValidUntil: profile.PreviousValidUntil}
	for rows.Next() {
		var deviceID string
		var want, have int64
		if err := rows.Scan(&deviceID, &want, &have); err != nil {
			return VPNProfileRollout{}, fmt.Errorf("scan profile rollout: %w", err)
		}
		out.Peers++
		if have >= want {
			out.Applied++
			continue
		}
		out.Pending++
		if len(out.PendingDeviceIDs) < limit {
			out.PendingDeviceIDs = append(out.PendingDeviceIDs, deviceID)
		}
	}
	if err := rows.Err(); err != nil {
		return VPNProfileRollout{}, fmt.Errorf("iterate profile rollout: %w", err)
	}
	out.PreviousKeyRetirable = out.Pending == 0
	if !out.PreviousKeyRetirable && profile.PreviousValidUntil != "" {
		if until, err := time.Parse(time.RFC3339Nano, profile.PreviousValidUntil); err == nil && !until.After(time.Now().UTC()) {
			out.PreviousKeyRetirable = true
		}
	}
	return out, nil
}

// DeviceConfigRevision is the config revision of the device's live peer, or
// zero when it has none. Devices compare it with their applied revision to
// recover a configuration change whose apply-config command they missed.
func (s *Store) DeviceConfigRevision(ctx context.Context, deviceID string) (int64, error) {
	var revision int64
	err := s.db.QueryRowContext(ctx, s.q(`
		SELECT config_revision FROM wireguard_peers WHERE device_id = ? AND revoked_at IS NULL
	`), deviceID).Scan(&revision)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("load device config revision: %w", err)
	}
	return revision, nil
}
