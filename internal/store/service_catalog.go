package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

// ServiceCatalogError carries a stable machine-readable code for failures of
// catalog, grant and scope operations. Kind is one of ErrInvalid, ErrNotFound
// or ErrConflict so callers can still use errors.Is.
type ServiceCatalogError struct {
	Kind    error
	Code    string
	Message string
}

func (e *ServiceCatalogError) Error() string { return e.Message }
func (e *ServiceCatalogError) Unwrap() error { return e.Kind }

func catalogErr(kind error, code, message string) error {
	return &ServiceCatalogError{Kind: kind, Code: code, Message: message}
}

// AuditMeta identifies who performed an administrative mutation. Service
// mutations write their audit event in the same transaction as the change.
type AuditMeta struct {
	ActorUserID string
	SourceIP    string
	RequestID   string
}

type sqlQueryer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) appendAuditTx(ctx context.Context, q sqlQueryer, meta AuditMeta, action, resourceType, resourceID string, details any) error {
	id, err := security.NewID()
	if err != nil {
		return err
	}
	raw := []byte("{}")
	if details != nil {
		if raw, err = json.Marshal(details); err != nil {
			raw = []byte("{}")
		}
	}
	if _, err := q.ExecContext(ctx, s.q(`
		INSERT INTO audit_events(
			id, actor_user_id, action, resource_type, resource_id,
			source_ip, request_id, details, created_at
		) VALUES(?, NULLIF(?, ''), ?, ?, ?, ?, ?, ?, ?)
	`), id, meta.ActorUserID, action, resourceType, resourceID, meta.SourceIP, meta.RequestID, string(raw), nowText()); err != nil {
		return fmt.Errorf("append audit: %w", err)
	}
	return nil
}

// bumpServicePolicyRevision advances the global service policy revision. It
// must run inside the transaction that changes anything affecting a device's
// effective service policy, so a revision never describes older content.
func (s *Store) bumpServicePolicyRevision(ctx context.Context, q sqlQueryer) (int64, error) {
	if _, err := q.ExecContext(ctx, s.q(`
		UPDATE service_policy_state SET revision = revision + 1, updated_at = ? WHERE id = 1
	`), nowText()); err != nil {
		return 0, fmt.Errorf("bump service policy revision: %w", err)
	}
	return s.readServicePolicyRevision(ctx, q)
}

func (s *Store) readServicePolicyRevision(ctx context.Context, q sqlQueryer) (int64, error) {
	var revision int64
	if err := q.QueryRowContext(ctx, "SELECT revision FROM service_policy_state WHERE id = 1").Scan(&revision); err != nil {
		return 0, fmt.Errorf("read service policy revision: %w", err)
	}
	return revision, nil
}

// ServicePolicyRevision returns the current global service policy revision.
func (s *Store) ServicePolicyRevision(ctx context.Context) (int64, error) {
	return s.readServicePolicyRevision(ctx, s.db)
}

const serviceDefinitionColumns = `
	d.id, r.revision, r.display_name, r.internal_dns_name, r.protocol, r.port,
	r.tls_policy, r.allowed_scopes, r.enabled, COALESCE(r.created_by_user_id, ''),
	d.created_at, r.created_at, r.connection_request`

func scanServiceDefinition(scan scanFunc) (domain.ServiceDefinition, error) {
	var def domain.ServiceDefinition
	var scopes, callback string
	var enabled int
	if err := scan(&def.ID, &def.Revision, &def.DisplayName, &def.InternalDNSName, &def.Protocol,
		&def.Port, &def.TLSPolicy, &scopes, &enabled, &def.UpdatedByUserID, &def.CreatedAt, &def.UpdatedAt, &callback); err != nil {
		return domain.ServiceDefinition{}, err
	}
	if callback != "" {
		var policy domain.ConnectionRequestPolicy
		if err := json.Unmarshal([]byte(callback), &policy); err != nil {
			return domain.ServiceDefinition{}, fmt.Errorf("decode callback policy: %w", err)
		}
		if err := policy.Validate(); err != nil || def.ID != domain.ServiceSunkarCWMPACS {
			return domain.ServiceDefinition{}, fmt.Errorf("invalid callback policy for service")
		}
		def.ConnectionRequest = &policy
	}
	def.Enabled = enabled != 0
	def.AllowedScopes = splitCSV(scopes)
	return def, nil
}

func splitCSV(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func (s *Store) loadServiceDefinition(ctx context.Context, q sqlQueryer, id string, lock bool) (domain.ServiceDefinition, error) {
	query := `SELECT ` + serviceDefinitionColumns + `
		FROM service_definitions d
		JOIN service_definition_revisions r ON r.service_id = d.id AND r.revision = d.current_revision
		WHERE d.id = ?`
	if lock && s.dialect == "postgres" {
		query += " FOR UPDATE OF d"
	}
	def, err := scanServiceDefinition(q.QueryRowContext(ctx, s.q(query), id).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ServiceDefinition{}, catalogErr(ErrNotFound, "service_not_found", "service is not in the catalog")
		}
		return domain.ServiceDefinition{}, fmt.Errorf("load service definition: %w", err)
	}
	return def, nil
}

// GetServiceDefinition returns the current revision of a catalog service.
func (s *Store) GetServiceDefinition(ctx context.Context, id string) (domain.ServiceDefinition, error) {
	return s.loadServiceDefinition(ctx, s.db, id, false)
}

// ServiceDefinitionFilter narrows ListServiceDefinitions.
type ServiceDefinitionFilter struct {
	Enabled *bool
}

// ListServiceDefinitions returns current service revisions ordered by id.
func (s *Store) ListServiceDefinitions(ctx context.Context, filter ServiceDefinitionFilter, limit, offset int) ([]domain.ServiceDefinition, int, error) {
	return s.listServiceDefinitions(ctx, s.db, filter, limit, offset)
}

func (s *Store) listServiceDefinitions(ctx context.Context, q sqlQueryer, filter ServiceDefinitionFilter, limit, offset int) ([]domain.ServiceDefinition, int, error) {
	where := ""
	var args []any
	if filter.Enabled != nil {
		where = " WHERE r.enabled = ?"
		args = append(args, boolInt(*filter.Enabled))
	}
	base := ` FROM service_definitions d
		JOIN service_definition_revisions r ON r.service_id = d.id AND r.revision = d.current_revision` + where

	var total int
	if err := q.QueryRowContext(ctx, s.q("SELECT COUNT(*)"+base), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count service definitions: %w", err)
	}
	rows, err := q.QueryContext(ctx, s.q("SELECT "+serviceDefinitionColumns+base+" ORDER BY d.id LIMIT ? OFFSET ?"),
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list service definitions: %w", err)
	}
	defer rows.Close()
	items := []domain.ServiceDefinition{}
	for rows.Next() {
		def, err := scanServiceDefinition(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan service definition: %w", err)
		}
		items = append(items, def)
	}
	return items, total, rows.Err()
}

// ListServiceDefinitionRevisions returns the revision history, newest first.
func (s *Store) ListServiceDefinitionRevisions(ctx context.Context, id string, limit, offset int) ([]domain.ServiceDefinition, int, error) {
	if _, err := s.loadServiceDefinition(ctx, s.db, id, false); err != nil {
		return nil, 0, err
	}
	var total int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM service_definition_revisions WHERE service_id = ?"), id).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count service revisions: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, s.q(`SELECT `+serviceDefinitionColumns+`
		FROM service_definitions d
		JOIN service_definition_revisions r ON r.service_id = d.id
		WHERE d.id = ?
		ORDER BY r.revision DESC LIMIT ? OFFSET ?`), id, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list service revisions: %w", err)
	}
	defer rows.Close()
	items := []domain.ServiceDefinition{}
	for rows.Next() {
		def, err := scanServiceDefinition(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan service revision: %w", err)
		}
		items = append(items, def)
	}
	return items, total, rows.Err()
}

// ServiceUpdateResult describes the outcome of a catalog update.
type ServiceUpdateResult struct {
	Definition     domain.ServiceDefinition
	PolicyRevision int64
	Changed        bool
}

// UpdateServiceDefinition appends a new immutable revision of a catalog
// service. expectedRevision guards against concurrent edits. Re-sending the
// content that is already current is a successful no-op, so retries are safe.
func (s *Store) UpdateServiceDefinition(ctx context.Context, meta AuditMeta, id string, expectedRevision int64, input domain.ServiceDefinitionInput) (ServiceUpdateResult, error) {
	if input.ConnectionRequest != nil && id != domain.ServiceSunkarCWMPACS {
		return ServiceUpdateResult{}, catalogErr(ErrInvalid, "invalid_service_definition", "connection_request is only supported for sunkarcwmp-acs")
	}
	if expectedRevision <= 0 {
		return ServiceUpdateResult{}, catalogErr(ErrInvalid, "expected_revision_required", "a positive expected_revision is required")
	}
	if err := input.Normalize(); err != nil {
		return ServiceUpdateResult{}, catalogErr(ErrInvalid, "invalid_service_definition", err.Error())
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServiceUpdateResult{}, fmt.Errorf("begin service update: %w", err)
	}
	defer tx.Rollback()

	current, err := s.loadServiceDefinition(ctx, tx, id, true)
	if err != nil {
		return ServiceUpdateResult{}, err
	}
	currentInput := domain.ServiceDefinitionInput{
		DisplayName: current.DisplayName, InternalDNSName: current.InternalDNSName,
		Protocol: current.Protocol, Port: current.Port, TLSPolicy: current.TLSPolicy,
		AllowedScopes: current.AllowedScopes, Enabled: current.Enabled, ConnectionRequest: current.ConnectionRequest,
	}
	if reflect.DeepEqual(currentInput, input) {
		revision, err := s.readServicePolicyRevision(ctx, tx)
		if err != nil {
			return ServiceUpdateResult{}, err
		}
		return ServiceUpdateResult{Definition: current, PolicyRevision: revision}, nil
	}
	if current.Revision != expectedRevision {
		return ServiceUpdateResult{}, catalogErr(ErrConflict, "service_revision_conflict", "service was modified; reload and retry with the current revision")
	}

	now := nowText()
	next := current.Revision + 1
	callback := ""
	if input.ConnectionRequest != nil {
		raw, err := json.Marshal(input.ConnectionRequest)
		if err != nil {
			return ServiceUpdateResult{}, fmt.Errorf("encode callback policy: %w", err)
		}
		callback = string(raw)
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO service_definition_revisions(
			service_id, revision, display_name, internal_dns_name, protocol, port,
			tls_policy, allowed_scopes, enabled, created_by_user_id, created_at, connection_request
		) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?, ?)
	`), id, next, input.DisplayName, input.InternalDNSName, input.Protocol, input.Port,
		input.TLSPolicy, strings.Join(input.AllowedScopes, ","), boolInt(input.Enabled), meta.ActorUserID, now, callback); err != nil {
		return ServiceUpdateResult{}, fmt.Errorf("insert service revision: %w", err)
	}
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE service_definitions SET current_revision = ?, updated_at = ?
		WHERE id = ? AND current_revision = ?
	`), next, now, id, current.Revision)
	if err != nil {
		return ServiceUpdateResult{}, fmt.Errorf("advance service revision: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return ServiceUpdateResult{}, catalogErr(ErrConflict, "service_revision_conflict", "service was modified; reload and retry with the current revision")
	}
	policyRevision, err := s.bumpServicePolicyRevision(ctx, tx)
	if err != nil {
		return ServiceUpdateResult{}, err
	}
	if err := s.appendAuditTx(ctx, tx, meta, "service.update", "service", id, map[string]any{
		"revision":           next,
		"previous_revision":  current.Revision,
		"enabled":            input.Enabled,
		"previous_enabled":   current.Enabled,
		"connection_request": input.ConnectionRequest,
		"internal_dns_name":  input.InternalDNSName,
		"port":               input.Port,
		"protocol":           input.Protocol,
		"tls_policy":         input.TLSPolicy,
		"allowed_scopes":     input.AllowedScopes,
		"policy_revision":    policyRevision,
	}); err != nil {
		return ServiceUpdateResult{}, err
	}
	updated, err := s.loadServiceDefinition(ctx, tx, id, false)
	if err != nil {
		return ServiceUpdateResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return ServiceUpdateResult{}, fmt.Errorf("commit service update: %w", err)
	}
	return ServiceUpdateResult{Definition: updated, PolicyRevision: policyRevision, Changed: true}, nil
}

const serviceGrantColumns = `
	id, service_id, scope_type, scope_id, effect, policy_revision,
	COALESCE(created_by_user_id, ''), created_at, COALESCE(revoked_at, ''),
	COALESCE(revoked_by_user_id, ''), COALESCE(revoked_policy_revision, 0)`

func scanServiceGrant(scan scanFunc) (domain.ServiceGrant, error) {
	var g domain.ServiceGrant
	err := scan(&g.ID, &g.ServiceID, &g.ScopeType, &g.ScopeID, &g.Effect, &g.PolicyRevision,
		&g.CreatedByUserID, &g.CreatedAt, &g.RevokedAt, &g.RevokedByUserID, &g.RevokedPolicyRevision)
	return g, err
}

// ServiceGrantResult describes the outcome of a grant mutation.
type ServiceGrantResult struct {
	Grant          domain.ServiceGrant
	PolicyRevision int64
	Changed        bool
}

// SetServiceGrant creates or replaces the active grant of a service for one
// scope. It is idempotent: repeating the same effect changes nothing. A
// replaced grant is kept as revoked history.
func (s *Store) SetServiceGrant(ctx context.Context, meta AuditMeta, serviceID, scopeType, scopeID, effect string) (ServiceGrantResult, error) {
	scopeType = strings.ToLower(strings.TrimSpace(scopeType))
	scopeID = strings.TrimSpace(scopeID)
	effect = strings.ToLower(strings.TrimSpace(effect))
	if !domain.ValidScopeType(scopeType) {
		return ServiceGrantResult{}, catalogErr(ErrInvalid, "invalid_scope_type", "scope_type must be one of tenant, site, group, device")
	}
	if !domain.ValidGrantEffect(effect) {
		return ServiceGrantResult{}, catalogErr(ErrInvalid, "invalid_effect", "effect must be allow or deny")
	}
	if err := domain.ValidateScopeID(scopeID); err != nil {
		return ServiceGrantResult{}, catalogErr(ErrInvalid, "invalid_scope_id", err.Error())
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServiceGrantResult{}, fmt.Errorf("begin service grant: %w", err)
	}
	defer tx.Rollback()

	def, err := s.loadServiceDefinition(ctx, tx, serviceID, true)
	if err != nil {
		return ServiceGrantResult{}, err
	}
	allowedScope := false
	for _, scope := range def.AllowedScopes {
		if scope == scopeType {
			allowedScope = true
		}
	}
	if !allowedScope {
		return ServiceGrantResult{}, catalogErr(ErrInvalid, "scope_not_allowed", "service does not accept grants for this scope type")
	}
	if scopeType == domain.ScopeDevice {
		var exists int
		if err := tx.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), scopeID).Scan(&exists); err != nil {
			return ServiceGrantResult{}, fmt.Errorf("check grant device: %w", err)
		}
		if exists == 0 {
			return ServiceGrantResult{}, catalogErr(ErrNotFound, "device_not_found", "device was not found")
		}
	}

	var previous *domain.ServiceGrant
	existing, err := scanServiceGrant(tx.QueryRowContext(ctx, s.q(`SELECT `+serviceGrantColumns+`
		FROM service_grants
		WHERE service_id = ? AND scope_type = ? AND scope_id = ? AND revoked_at IS NULL`),
		serviceID, scopeType, scopeID).Scan)
	switch {
	case err == nil:
		if existing.Effect == effect {
			revision, err := s.readServicePolicyRevision(ctx, tx)
			if err != nil {
				return ServiceGrantResult{}, err
			}
			return ServiceGrantResult{Grant: existing, PolicyRevision: revision}, nil
		}
		previous = &existing
	case errors.Is(err, sql.ErrNoRows):
	default:
		return ServiceGrantResult{}, fmt.Errorf("load active grant: %w", err)
	}

	policyRevision, err := s.bumpServicePolicyRevision(ctx, tx)
	if err != nil {
		return ServiceGrantResult{}, err
	}
	now := nowText()
	if previous != nil {
		if _, err := tx.ExecContext(ctx, s.q(`
			UPDATE service_grants
			SET revoked_at = ?, revoked_by_user_id = NULLIF(?, ''), revoked_policy_revision = ?
			WHERE id = ? AND revoked_at IS NULL
		`), now, meta.ActorUserID, policyRevision, previous.ID); err != nil {
			return ServiceGrantResult{}, fmt.Errorf("supersede service grant: %w", err)
		}
	}
	id, err := security.NewID()
	if err != nil {
		return ServiceGrantResult{}, err
	}
	if _, err := tx.ExecContext(ctx, s.q(`
		INSERT INTO service_grants(
			id, service_id, scope_type, scope_id, effect, policy_revision, created_by_user_id, created_at
		) VALUES(?, ?, ?, ?, ?, ?, NULLIF(?, ''), ?)
	`), id, serviceID, scopeType, scopeID, effect, policyRevision, meta.ActorUserID, now); err != nil {
		return ServiceGrantResult{}, mapConflict(err, "insert service grant")
	}
	details := map[string]any{
		"grant_id": id, "service_id": serviceID, "scope_type": scopeType, "scope_id": scopeID,
		"effect": effect, "policy_revision": policyRevision,
	}
	if previous != nil {
		details["previous_effect"] = previous.Effect
		details["previous_grant_id"] = previous.ID
	}
	if err := s.appendAuditTx(ctx, tx, meta, "service_grant.set", "service_grant", id, details); err != nil {
		return ServiceGrantResult{}, err
	}
	grant, err := scanServiceGrant(tx.QueryRowContext(ctx, s.q("SELECT "+serviceGrantColumns+" FROM service_grants WHERE id = ?"), id).Scan)
	if err != nil {
		return ServiceGrantResult{}, fmt.Errorf("reload service grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ServiceGrantResult{}, fmt.Errorf("commit service grant: %w", err)
	}
	return ServiceGrantResult{Grant: grant, PolicyRevision: policyRevision, Changed: true}, nil
}

// RevokeServiceGrant withdraws an active grant. Revoking a grant that is
// already revoked succeeds without a new revision.
func (s *Store) RevokeServiceGrant(ctx context.Context, meta AuditMeta, serviceID, grantID string) (ServiceGrantResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ServiceGrantResult{}, fmt.Errorf("begin service grant revoke: %w", err)
	}
	defer tx.Rollback()

	grant, err := scanServiceGrant(tx.QueryRowContext(ctx, s.q("SELECT "+serviceGrantColumns+" FROM service_grants WHERE id = ? AND service_id = ?"),
		grantID, serviceID).Scan)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ServiceGrantResult{}, catalogErr(ErrNotFound, "grant_not_found", "service grant was not found")
		}
		return ServiceGrantResult{}, fmt.Errorf("load service grant: %w", err)
	}
	if grant.RevokedAt != "" {
		revision, err := s.readServicePolicyRevision(ctx, tx)
		if err != nil {
			return ServiceGrantResult{}, err
		}
		return ServiceGrantResult{Grant: grant, PolicyRevision: revision}, nil
	}

	policyRevision, err := s.bumpServicePolicyRevision(ctx, tx)
	if err != nil {
		return ServiceGrantResult{}, err
	}
	result, err := tx.ExecContext(ctx, s.q(`
		UPDATE service_grants
		SET revoked_at = ?, revoked_by_user_id = NULLIF(?, ''), revoked_policy_revision = ?
		WHERE id = ? AND revoked_at IS NULL
	`), nowText(), meta.ActorUserID, policyRevision, grantID)
	if err != nil {
		return ServiceGrantResult{}, fmt.Errorf("revoke service grant: %w", err)
	}
	if n, err := result.RowsAffected(); err == nil && n == 0 {
		return ServiceGrantResult{}, catalogErr(ErrConflict, "grant_state_conflict", "service grant changed concurrently")
	}
	if err := s.appendAuditTx(ctx, tx, meta, "service_grant.revoke", "service_grant", grantID, map[string]any{
		"service_id": serviceID, "scope_type": grant.ScopeType, "scope_id": grant.ScopeID,
		"effect": grant.Effect, "policy_revision": policyRevision,
	}); err != nil {
		return ServiceGrantResult{}, err
	}
	revoked, err := scanServiceGrant(tx.QueryRowContext(ctx, s.q("SELECT "+serviceGrantColumns+" FROM service_grants WHERE id = ?"), grantID).Scan)
	if err != nil {
		return ServiceGrantResult{}, fmt.Errorf("reload service grant: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return ServiceGrantResult{}, fmt.Errorf("commit service grant revoke: %w", err)
	}
	return ServiceGrantResult{Grant: revoked, PolicyRevision: policyRevision, Changed: true}, nil
}

// ServiceGrantFilter narrows ListServiceGrants.
type ServiceGrantFilter struct {
	ServiceID      string
	ScopeType      string
	ScopeID        string
	Effect         string
	IncludeRevoked bool
	Sort           string
}

var grantSortColumns = map[string]string{
	"created_at": "created_at",
	"scope_type": "scope_type",
	"scope_id":   "scope_id",
	"effect":     "effect",
}

// ListServiceGrants returns grants of one service with filtering, sorting and
// pagination. Revoked grants are excluded unless IncludeRevoked is set.
func (s *Store) ListServiceGrants(ctx context.Context, filter ServiceGrantFilter, limit, offset int) ([]domain.ServiceGrant, int, error) {
	if _, err := s.loadServiceDefinition(ctx, s.db, filter.ServiceID, false); err != nil {
		return nil, 0, err
	}
	where := []string{"service_id = ?"}
	args := []any{filter.ServiceID}
	if filter.ScopeType != "" {
		where = append(where, "scope_type = ?")
		args = append(args, filter.ScopeType)
	}
	if filter.ScopeID != "" {
		where = append(where, "scope_id = ?")
		args = append(args, filter.ScopeID)
	}
	if filter.Effect != "" {
		where = append(where, "effect = ?")
		args = append(args, filter.Effect)
	}
	if !filter.IncludeRevoked {
		where = append(where, "revoked_at IS NULL")
	}

	sortField, desc := strings.TrimPrefix(filter.Sort, "-"), strings.HasPrefix(filter.Sort, "-")
	if filter.Sort == "" {
		sortField, desc = "created_at", true
	}
	column, ok := grantSortColumns[sortField]
	if !ok {
		return nil, 0, catalogErr(ErrInvalid, "invalid_sort", "sort must be one of created_at, scope_type, scope_id, effect, optionally prefixed with '-'")
	}
	direction := "ASC"
	if desc {
		direction = "DESC"
	}

	clause := " FROM service_grants WHERE " + strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*)"+clause), args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count service grants: %w", err)
	}
	rows, err := s.db.QueryContext(ctx,
		s.q("SELECT "+serviceGrantColumns+clause+" ORDER BY "+column+" "+direction+", id ASC LIMIT ? OFFSET ?"),
		append(args, limit, offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("list service grants: %w", err)
	}
	defer rows.Close()
	items := []domain.ServiceGrant{}
	for rows.Next() {
		grant, err := scanServiceGrant(rows.Scan)
		if err != nil {
			return nil, 0, fmt.Errorf("scan service grant: %w", err)
		}
		items = append(items, grant)
	}
	return items, total, rows.Err()
}

func (s *Store) loadDeviceScopes(ctx context.Context, q sqlQueryer, deviceID string) (domain.DeviceScopes, error) {
	rows, err := q.QueryContext(ctx, s.q(`
		SELECT scope_type, scope_id FROM device_scope_memberships
		WHERE device_id = ? ORDER BY scope_type, scope_id
	`), deviceID)
	if err != nil {
		return domain.DeviceScopes{}, fmt.Errorf("load device scopes: %w", err)
	}
	defer rows.Close()
	scopes := domain.DeviceScopes{GroupIDs: []string{}}
	for rows.Next() {
		var scopeType, scopeID string
		if err := rows.Scan(&scopeType, &scopeID); err != nil {
			return domain.DeviceScopes{}, fmt.Errorf("scan device scope: %w", err)
		}
		switch scopeType {
		case domain.ScopeTenant:
			scopes.TenantID = scopeID
		case domain.ScopeSite:
			scopes.SiteID = scopeID
		case domain.ScopeGroup:
			scopes.GroupIDs = append(scopes.GroupIDs, scopeID)
		}
	}
	if err := rows.Err(); err != nil {
		return scopes, err
	}
	if err := rows.Close(); err != nil {
		return scopes, err
	}
	if err := s.validateScopeOwners(ctx, q, scopes); err != nil {
		return domain.DeviceScopes{}, err
	}
	return scopes, nil
}

func (s *Store) deviceExists(ctx context.Context, q sqlQueryer, deviceID string) error {
	var exists int
	if err := q.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE id = ?"), deviceID).Scan(&exists); err != nil {
		return fmt.Errorf("check device: %w", err)
	}
	if exists == 0 {
		return catalogErr(ErrNotFound, "device_not_found", "device was not found")
	}
	return nil
}

// GetDeviceScopes returns the tenant, site and group membership of a device.
func (s *Store) GetDeviceScopes(ctx context.Context, deviceID string) (domain.DeviceScopes, error) {
	if err := s.deviceExists(ctx, s.db, deviceID); err != nil {
		return domain.DeviceScopes{}, err
	}
	return s.loadDeviceScopes(ctx, s.db, deviceID)
}

// DeviceScopesResult describes the outcome of a membership update.
type DeviceScopesResult struct {
	Scopes         domain.DeviceScopes
	PolicyRevision int64
	Changed        bool
}

// SetDeviceScopes replaces the scope membership of a device. Because
// membership decides which tenant/site/group grants apply, it is a policy
// mutation: it bumps the policy revision and is audited.
func (s *Store) SetDeviceScopes(ctx context.Context, meta AuditMeta, deviceID string, scopes domain.DeviceScopes) (DeviceScopesResult, error) {
	if err := scopes.Normalize(); err != nil {
		return DeviceScopesResult{}, catalogErr(ErrInvalid, "invalid_scope_id", err.Error())
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DeviceScopesResult{}, fmt.Errorf("begin device scope update: %w", err)
	}
	defer tx.Rollback()

	// Serialize membership and owner changes before reading the current scopes.
	if _, err := tx.ExecContext(ctx, "UPDATE service_policy_state SET revision = revision WHERE id = 1"); err != nil {
		return DeviceScopesResult{}, fmt.Errorf("lock scope policy: %w", err)
	}

	if err := s.deviceExists(ctx, tx, deviceID); err != nil {
		return DeviceScopesResult{}, err
	}
	current, err := s.loadDeviceScopes(ctx, tx, deviceID)
	if err != nil {
		return DeviceScopesResult{}, err
	}
	if reflect.DeepEqual(current, scopes) {
		revision, err := s.readServicePolicyRevision(ctx, tx)
		if err != nil {
			return DeviceScopesResult{}, err
		}
		return DeviceScopesResult{Scopes: current, PolicyRevision: revision}, nil
	}

	if err := s.bindScopeOwnersTx(ctx, tx, scopes); err != nil {
		return DeviceScopesResult{}, err
	}

	if _, err := tx.ExecContext(ctx, s.q("DELETE FROM device_scope_memberships WHERE device_id = ?"), deviceID); err != nil {
		return DeviceScopesResult{}, fmt.Errorf("clear device scopes: %w", err)
	}
	now := nowText()
	insert := func(scopeType, scopeID string) error {
		_, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO device_scope_memberships(device_id, scope_type, scope_id, created_at)
			VALUES(?, ?, ?, ?)
		`), deviceID, scopeType, scopeID, now)
		return err
	}
	if scopes.TenantID != "" {
		if err := insert(domain.ScopeTenant, scopes.TenantID); err != nil {
			return DeviceScopesResult{}, fmt.Errorf("insert tenant scope: %w", err)
		}
	}
	if scopes.SiteID != "" {
		if err := insert(domain.ScopeSite, scopes.SiteID); err != nil {
			return DeviceScopesResult{}, fmt.Errorf("insert site scope: %w", err)
		}
	}
	for _, group := range scopes.GroupIDs {
		if err := insert(domain.ScopeGroup, group); err != nil {
			return DeviceScopesResult{}, fmt.Errorf("insert group scope: %w", err)
		}
	}
	policyRevision, err := s.bumpServicePolicyRevision(ctx, tx)
	if err != nil {
		return DeviceScopesResult{}, err
	}
	if err := s.appendAuditTx(ctx, tx, meta, "device.scopes.update", "device", deviceID, map[string]any{
		"tenant_id": scopes.TenantID, "site_id": scopes.SiteID, "group_ids": scopes.GroupIDs,
		"policy_revision": policyRevision,
	}); err != nil {
		return DeviceScopesResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return DeviceScopesResult{}, fmt.Errorf("commit device scope update: %w", err)
	}
	return DeviceScopesResult{Scopes: scopes, PolicyRevision: policyRevision, Changed: true}, nil
}

type evaluatedDevicePolicy struct {
	revision    int64
	accessState string
	scopes      domain.DeviceScopes
	definitions []domain.ServiceDefinition
	decisions   []domain.ServiceAccessDecision
}

// evaluateDevicePolicy resolves every catalog service for one device. The
// revision and content are read in one database snapshot.
func (s *Store) evaluateDevicePolicy(ctx context.Context, deviceID string) (evaluatedDevicePolicy, error) {
	var out evaluatedDevicePolicy
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable, ReadOnly: true})
	if err != nil {
		return out, fmt.Errorf("begin device policy snapshot: %w", err)
	}
	defer tx.Rollback()
	revision, err := s.readServicePolicyRevision(ctx, tx)
	if err != nil {
		return out, err
	}
	out.revision = revision

	var status string
	var suspended int
	if err := tx.QueryRowContext(ctx, s.q("SELECT status, suspended FROM devices WHERE id = ?"), deviceID).Scan(&status, &suspended); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return out, catalogErr(ErrNotFound, "device_not_found", "device was not found")
		}
		return out, fmt.Errorf("load device state: %w", err)
	}
	out.accessState = domain.DeviceAccessState(status, suspended != 0)
	active := out.accessState == domain.AccessStateActive

	if out.scopes, err = s.loadDeviceScopes(ctx, tx, deviceID); err != nil {
		return out, err
	}
	if out.definitions, _, err = s.listServiceDefinitions(ctx, tx, ServiceDefinitionFilter{}, 1000, 0); err != nil {
		return out, err
	}

	var grants []domain.ServiceGrant
	if active {
		conditions := []string{"(scope_type = 'device' AND scope_id = ?)"}
		args := []any{deviceID}
		if out.scopes.TenantID != "" {
			conditions = append(conditions, "(scope_type = 'tenant' AND scope_id = ?)")
			args = append(args, out.scopes.TenantID)
		}
		if out.scopes.SiteID != "" {
			conditions = append(conditions, "(scope_type = 'site' AND scope_id = ?)")
			args = append(args, out.scopes.SiteID)
		}
		for _, group := range out.scopes.GroupIDs {
			conditions = append(conditions, "(scope_type = 'group' AND scope_id = ?)")
			args = append(args, group)
		}
		rows, err := tx.QueryContext(ctx, s.q("SELECT "+serviceGrantColumns+
			" FROM service_grants WHERE revoked_at IS NULL AND ("+strings.Join(conditions, " OR ")+")"), args...)
		if err != nil {
			return out, fmt.Errorf("load device grants: %w", err)
		}
		defer rows.Close()
		for rows.Next() {
			grant, err := scanServiceGrant(rows.Scan)
			if err != nil {
				return out, fmt.Errorf("scan device grant: %w", err)
			}
			grants = append(grants, grant)
		}
		if err := rows.Err(); err != nil {
			return out, err
		}
	}

	out.decisions = make([]domain.ServiceAccessDecision, len(out.definitions))
	for i, def := range out.definitions {
		out.decisions[i] = domain.EvaluateServiceAccess(def, deviceID, active, out.scopes, grants)
	}
	return out, nil
}

// DeviceServicePolicy returns the effective, non-secret service policy of a
// device. Services are listed only when the device is active and an explicit
// allow grant resolves; suspended, revoking, revoked and pending devices get
// an empty list.
func (s *Store) DeviceServicePolicy(ctx context.Context, deviceID string) (domain.DeviceServicePolicy, error) {
	return s.DeviceServicePolicyObserved(ctx, deviceID, nil)
}

// DeviceServicePolicyObserved emits decisions to a local observer after evaluating
// a consistent snapshot. They never become part of the device response.
func (s *Store) DeviceServicePolicyObserved(ctx context.Context, deviceID string, observe func(string, domain.ServiceAccessDecision)) (domain.DeviceServicePolicy, error) {
	evaluated, err := s.evaluateDevicePolicy(ctx, deviceID)
	if err != nil {
		return domain.DeviceServicePolicy{}, err
	}
	now := time.Now().UTC()
	policy := domain.DeviceServicePolicy{
		DeviceID:     deviceID,
		AccessState:  evaluated.accessState,
		Revision:     evaluated.revision,
		GeneratedAt:  now.Format(time.RFC3339Nano),
		ExpiresAt:    now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		MandatoryVPN: true,
		Services:     []domain.DeviceServiceEndpoint{},
	}
	for i, def := range evaluated.definitions {
		if observe != nil {
			observe(def.ID, evaluated.decisions[i])
		}
		if !evaluated.decisions[i].Allowed {
			continue
		}
		policy.Services = append(policy.Services, domain.DeviceServiceEndpoint{
			ID: def.ID, DisplayName: def.DisplayName, Host: def.InternalDNSName,
			Port: def.Port, Protocol: def.Protocol, TLSPolicy: def.TLSPolicy, Revision: def.Revision, ConnectionRequest: def.ConnectionRequest,
		})
	}
	return policy, nil
}

// AdminDevicePolicy returns the same resolution as DeviceServicePolicy, with
// per-service decisions and reasons, for administrators.
func (s *Store) AdminDevicePolicy(ctx context.Context, deviceID string) (domain.AdminDevicePolicy, error) {
	evaluated, err := s.evaluateDevicePolicy(ctx, deviceID)
	if err != nil {
		return domain.AdminDevicePolicy{}, err
	}
	policy := domain.AdminDevicePolicy{
		DeviceID:    deviceID,
		AccessState: evaluated.accessState,
		Revision:    evaluated.revision,
		Scopes:      evaluated.scopes,
		Services:    make([]domain.AdminServiceDecision, 0, len(evaluated.definitions)),
	}
	for i, def := range evaluated.definitions {
		policy.Services = append(policy.Services, domain.AdminServiceDecision{
			ServiceID: def.ID, ServiceRevision: def.Revision, DisplayName: def.DisplayName,
			Enabled: def.Enabled, ServiceAccessDecision: evaluated.decisions[i],
		})
	}
	return policy, nil
}
