package domain

type WireGuardReconcileItem struct {
	PeerID            string `json:"peer_id"`
	DeviceID          string `json:"device_id"`
	ProfileID         string `json:"profile_id"`
	PublicKey         string `json:"public_key"`
	PreviousPublicKey string `json:"previous_public_key,omitempty"`
	AssignedAddress   string `json:"assigned_address"`
	DesiredState      string `json:"desired_state"`
	ConfigRevision    int64  `json:"config_revision"`
	AppliedRevision   int64  `json:"applied_revision"`
	ReconcileState    string `json:"reconcile_state"`
}
