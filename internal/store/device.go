package store

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
)

func normalizeMAC(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	mac, err := net.ParseMAC(value)
	if err != nil {
		return "", fmt.Errorf("invalid MAC address")
	}
	return strings.ToLower(mac.String()), nil
}

func (s *Store) CreateDevice(ctx context.Context, input domain.DeviceCreate) (domain.Device, error) {
	input.Name = strings.TrimSpace(input.Name)
	input.DeviceUUID = strings.TrimSpace(input.DeviceUUID)
	input.SerialNumber = strings.TrimSpace(input.SerialNumber)
	if input.Name == "" || len(input.Name) > 200 {
		return domain.Device{}, fmt.Errorf("invalid device name")
	}
	if input.DeviceUUID == "" || len(input.DeviceUUID) > 200 {
		return domain.Device{}, fmt.Errorf("invalid device UUID")
	}
	mac, err := normalizeMAC(input.PrimaryMAC)
	if err != nil {
		return domain.Device{}, err
	}
	input.PrimaryMAC = mac

	var exists int
	if err := s.db.QueryRowContext(ctx, s.q("SELECT COUNT(*) FROM devices WHERE device_uuid = ?"), input.DeviceUUID).Scan(&exists); err != nil {
		return domain.Device{}, fmt.Errorf("check device identity: %w", err)
	}
	if exists != 0 {
		return domain.Device{}, ErrConflict
	}

	id, err := security.NewID()
	if err != nil {
		return domain.Device{}, err
	}
	now := nowText()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Device{}, fmt.Errorf("begin create device: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, s.q(`
		INSERT INTO devices(
			id, name, device_uuid, serial_number, primary_mac,
			status, suspended, created_at, updated_at
		) VALUES(?, ?, ?, ?, ?, 'pending', 0, ?, ?)
	`), id, input.Name, input.DeviceUUID, input.SerialNumber, input.PrimaryMAC, now, now)
	if err != nil {
		return domain.Device{}, fmt.Errorf("insert device: %w", err)
	}

	identities := [][2]string{{"device_uuid", input.DeviceUUID}}
	if input.SerialNumber != "" {
		identities = append(identities, [2]string{"serial_number", input.SerialNumber})
	}
	if input.PrimaryMAC != "" {
		identities = append(identities, [2]string{"mac", input.PrimaryMAC})
	}
	for _, identity := range identities {
		identityID, err := security.NewID()
		if err != nil {
			return domain.Device{}, err
		}
		if _, err := tx.ExecContext(ctx, s.q(`
			INSERT INTO device_identities(id, device_id, kind, value, verified, created_at)
			VALUES(?, ?, ?, ?, 0, ?)
		`), identityID, id, identity[0], identity[1], now); err != nil {
			return domain.Device{}, fmt.Errorf("insert device identity %s: %w", identity[0], err)
		}
	}

	if err := tx.Commit(); err != nil {
		return domain.Device{}, fmt.Errorf("commit device: %w", err)
	}

	return domain.Device{
		ID:           id,
		Name:         input.Name,
		DeviceUUID:   input.DeviceUUID,
		SerialNumber: input.SerialNumber,
		PrimaryMAC:   input.PrimaryMAC,
		Status:       "pending",
		CreatedAt:    now,
		UpdatedAt:    now,
	}, nil
}

func (s *Store) GetDevice(ctx context.Context, id string) (domain.Device, error) {
	return s.getDeviceBy(ctx, "id", id)
}

func (s *Store) GetDeviceByUUID(ctx context.Context, deviceUUID string) (domain.Device, error) {
	return s.getDeviceBy(ctx, "device_uuid", deviceUUID)
}

func (s *Store) getDeviceBy(ctx context.Context, column, value string) (domain.Device, error) {
	if column != "id" && column != "device_uuid" {
		return domain.Device{}, fmt.Errorf("invalid lookup column")
	}

	var d domain.Device
	var suspended int
	var lastSeen sql.NullString
	query := fmt.Sprintf(`
		SELECT id, name, device_uuid, serial_number, primary_mac, status,
		       suspended, created_at, updated_at, last_seen_at
		FROM devices WHERE %s = ?
	`, column)
	err := s.db.QueryRowContext(ctx, s.q(query), value).Scan(
		&d.ID, &d.Name, &d.DeviceUUID, &d.SerialNumber, &d.PrimaryMAC, &d.Status,
		&suspended, &d.CreatedAt, &d.UpdatedAt, &lastSeen,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Device{}, ErrNotFound
		}
		return domain.Device{}, fmt.Errorf("get device: %w", err)
	}
	d.Suspended = suspended != 0
	if lastSeen.Valid {
		d.LastSeenAt = lastSeen.String
	}
	return d, nil
}

func (s *Store) ListDevices(ctx context.Context, limit, offset int) ([]domain.Device, int, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	var total int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM devices").Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count devices: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, s.q(`
		SELECT id, name, device_uuid, serial_number, primary_mac, status,
		       suspended, created_at, updated_at, last_seen_at
		FROM devices
		ORDER BY created_at DESC, id
		LIMIT ? OFFSET ?
	`), limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list devices: %w", err)
	}
	defer rows.Close()

	devices := make([]domain.Device, 0)
	for rows.Next() {
		var d domain.Device
		var suspended int
		var lastSeen sql.NullString
		if err := rows.Scan(
			&d.ID, &d.Name, &d.DeviceUUID, &d.SerialNumber, &d.PrimaryMAC, &d.Status,
			&suspended, &d.CreatedAt, &d.UpdatedAt, &lastSeen,
		); err != nil {
			return nil, 0, fmt.Errorf("scan device: %w", err)
		}
		d.Suspended = suspended != 0
		if lastSeen.Valid {
			d.LastSeenAt = lastSeen.String
		}
		devices = append(devices, d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate devices: %w", err)
	}
	return devices, total, nil
}

func (s *Store) SetDeviceSuspended(ctx context.Context, id string, suspended bool) error {
	value := 0
	status := "active"
	if suspended {
		value = 1
		status = "suspended"
	}
	result, err := s.db.ExecContext(ctx, s.q(`
		UPDATE devices SET suspended = ?, status = ?, updated_at = ? WHERE id = ?
	`), value, status, nowText(), id)
	if err != nil {
		return fmt.Errorf("update device suspension: %w", err)
	}
	n, err := result.RowsAffected()
	if err == nil && n == 0 {
		return ErrNotFound
	}
	return nil
}
