package httpapi

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/1day0fmylife/Guardian/internal/domain"
	"github.com/1day0fmylife/Guardian/internal/security"
	"golang.org/x/net/websocket"
)

const (
	deviceSignalProtocolVersion = 1
	deviceSignalKeepalive       = 30 * time.Second
	deviceSignalWriteTimeout    = 10 * time.Second
)

type deviceSignal struct {
	Type     string `json:"type"`
	Version  int    `json:"version,omitempty"`
	Revision int64  `json:"revision,omitempty"`
}

type deviceSignalSubscriber struct {
	wake       chan deviceSignal
	policy     chan struct{}
	revision   int64
	reauth     chan struct{}
	reauthOnce sync.Once
}

type deviceSignalHub struct {
	mu          sync.RWMutex
	subscribers map[string]map[*deviceSignalSubscriber]struct{}
}

func newDeviceSignalHub() *deviceSignalHub {
	return &deviceSignalHub{subscribers: make(map[string]map[*deviceSignalSubscriber]struct{})}
}

func (h *deviceSignalHub) subscribe(deviceID string) (*deviceSignalSubscriber, func()) {
	subscriber := &deviceSignalSubscriber{wake: make(chan deviceSignal, 1), policy: make(chan struct{}, 1), reauth: make(chan struct{})}
	h.mu.Lock()
	if h.subscribers[deviceID] == nil {
		h.subscribers[deviceID] = make(map[*deviceSignalSubscriber]struct{})
	}
	h.subscribers[deviceID][subscriber] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	return subscriber, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subscribers[deviceID], subscriber)
			if len(h.subscribers[deviceID]) == 0 {
				delete(h.subscribers, deviceID)
			}
			h.mu.Unlock()
		})
	}
}

func (h *deviceSignalHub) publish(deviceID string, signal deviceSignal) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for subscriber := range h.subscribers[deviceID] {
		if signal.Type == "reauth_required" {
			subscriber.reauthOnce.Do(func() { close(subscriber.reauth) })
			continue
		}
		select {
		case subscriber.wake <- signal:
		default:
			// Ordinary wake-up hints coalesce. Command state itself remains
			// durable in the database and reconnect also causes an immediate poll.
		}
	}
}

// Policy hints have their own coalesced queue so command traffic cannot hide
// revocation. The maximum committed revision wins, including reordered writers.
func (h *deviceSignalHub) publishPolicy(deviceID string, revision int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, subscribers := range h.subscribers {
		if deviceID != "" && id != deviceID {
			continue
		}
		for subscriber := range subscribers {
			if revision <= subscriber.revision {
				continue
			}
			subscriber.revision = revision
			select {
			case subscriber.policy <- struct{}{}:
			default:
			}
		}
	}
}

func (h *deviceSignalHub) policyRevision(subscriber *deviceSignalSubscriber) int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return subscriber.revision
}

var deviceSignalHubs sync.Map // map[*Server]*deviceSignalHub

func signalHubFor(server *Server) *deviceSignalHub {
	value, _ := deviceSignalHubs.LoadOrStore(server, newDeviceSignalHub())
	return value.(*deviceSignalHub)
}

// WebSocketHandler layers the outbound-device wake-up channel over the supplied
// Guardian HTTP handler. This keeps the realtime transport independent from the
// admin/management router composition and makes the handler order explicit.
func (s *Server) WebSocketHandler(next http.Handler) http.Handler {
	if next == nil {
		next = s.ManagementHandler()
	}
	mux := http.NewServeMux()
	wsHandler := s.requestIDMiddleware(s.securityHeaders(http.HandlerFunc(s.deviceWebSocket)))
	mux.Handle("GET /api/v1/device/ws", wsHandler)
	mux.Handle("/", s.deviceCommandSignalMiddleware(next))
	return mux
}

// WebSocketManagementHandler is retained for compatibility with deployments
// that only need the original management API surface.
func (s *Server) WebSocketManagementHandler() http.Handler {
	return s.WebSocketHandler(s.ManagementHandler())
}

func (s *Server) deviceWebSocket(w http.ResponseWriter, r *http.Request) {
	token := deviceToken(r.Header.Get("Authorization"))
	if token == "" {
		w.Header().Set("WWW-Authenticate", `Guardian-Device realm="Guardian"`)
		writeError(w, http.StatusUnauthorized, "device_authentication_required", "device credential is required")
		return
	}
	principal, err := s.store.DevicePrincipalByCredential(r.Context(), security.HashToken(token))
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Guardian-Device realm="Guardian"`)
		writeError(w, http.StatusUnauthorized, "invalid_device_credential", "device credential is invalid or revoked")
		return
	}

	wsServer := websocket.Server{
		// Guardian device clients are not browsers and do not send Origin. The
		// authenticated Guardian-Device credential above is the trust boundary.
		Handshake: func(*websocket.Config, *http.Request) error { return nil },
		Handler: func(conn *websocket.Conn) {
			s.serveDeviceSignals(conn, principal)
		},
	}
	wsServer.ServeHTTP(w, r)
}

func (s *Server) serveDeviceSignals(conn *websocket.Conn, principal domain.DevicePrincipal) {
	conn.MaxPayloadBytes = 4096
	subscriber, unsubscribe := signalHubFor(s).subscribe(principal.DeviceID)
	defer unsubscribe()
	defer conn.Close()

	// Reconnect is itself a wake-up. This closes the race where a command was
	// committed just before the device established/re-established the socket.
	if err := sendDeviceSignal(conn, deviceSignal{Type: "ready", Version: deviceSignalProtocolVersion}); err != nil {
		return
	}
	if err := sendDeviceSignal(conn, deviceSignal{Type: "commands_available"}); err != nil {
		return
	}

	credentialHash := security.HashToken(deviceToken(conn.Request().Header.Get("Authorization")))
	if err := s.refreshDeviceSignalState(conn.Request().Context(), principal.DeviceID, credentialHash); err != nil {
		return
	}

	keepalive := time.NewTicker(deviceSignalKeepalive)
	defer keepalive.Stop()
	for {
		select {
		case <-subscriber.reauth:
			_ = sendDeviceSignal(conn, deviceSignal{Type: "reauth_required"})
			return
		case <-subscriber.policy:
			revision := signalHubFor(s).policyRevision(subscriber)
			if err := sendDeviceSignal(conn, deviceSignal{Type: "policy_changed", Revision: revision}); err != nil {
				return
			}
		case signal := <-subscriber.wake:
			if err := sendDeviceSignal(conn, signal); err != nil {
				return
			}
		case <-keepalive.C:
			// Recheck durable state even when mutations came from another instance.
			if err := s.refreshDeviceSignalState(conn.Request().Context(), principal.DeviceID, credentialHash); err != nil {
				_ = sendDeviceSignal(conn, deviceSignal{Type: "reauth_required"})
				return
			}
			if err := sendDeviceSignal(conn, deviceSignal{Type: "keepalive"}); err != nil {
				return
			}
		}
	}
}

// refreshDeviceSignalState uses the database, never cached authorization.
func (s *Server) refreshDeviceSignalState(ctx context.Context, deviceID, credentialHash string) error {
	if _, err := s.store.DevicePrincipalByCredential(ctx, credentialHash); err != nil {
		return err
	}
	revision, err := s.store.ServicePolicyRevision(ctx)
	if err != nil {
		return err
	}
	signalHubFor(s).publishPolicy(deviceID, revision)
	return nil
}

func sendDeviceSignal(conn *websocket.Conn, signal deviceSignal) error {
	if err := conn.SetWriteDeadline(time.Now().Add(deviceSignalWriteTimeout)); err != nil {
		return err
	}
	err := websocket.JSON.Send(conn, signal)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func (s *Server) deviceCommandSignalMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		deviceID, signalType, ok := deviceMutationSignal(r.Method, r.URL.Path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		capture := &statusCapture{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(capture, r)
		if capture.status < 200 || capture.status >= 300 {
			return
		}
		signalHubFor(s).publish(deviceID, deviceSignal{Type: signalType})
		if revision, err := s.store.ServicePolicyRevision(r.Context()); err == nil {
			signalHubFor(s).publishPolicy(deviceID, revision)
		}
	})
}

type statusCapture struct {
	http.ResponseWriter
	status int
}

func (w *statusCapture) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusCapture) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(data)
}

func deviceMutationSignal(method, requestPath string) (deviceID, signalType string, ok bool) {
	if method != http.MethodPost {
		return "", "", false
	}
	parts := strings.Split(strings.Trim(requestPath, "/"), "/")
	if len(parts) < 5 || parts[0] != "api" || parts[1] != "v1" || parts[2] != "devices" || strings.TrimSpace(parts[3]) == "" {
		return "", "", false
	}
	deviceID = parts[3]
	if len(parts) == 5 {
		switch parts[4] {
		case "commands", "suspend", "resume", "revoke":
			return deviceID, "commands_available", true
		}
	}
	if len(parts) == 6 && parts[4] == "credentials" && parts[5] == "revoke" {
		return deviceID, "reauth_required", true
	}
	return "", "", false
}
