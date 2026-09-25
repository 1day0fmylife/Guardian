package httpapi

import (
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
	Type    string `json:"type"`
	Version int    `json:"version,omitempty"`
}

type deviceSignalHub struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan deviceSignal]struct{}
}

func newDeviceSignalHub() *deviceSignalHub {
	return &deviceSignalHub{subscribers: make(map[string]map[chan deviceSignal]struct{})}
}

func (h *deviceSignalHub) subscribe(deviceID string) (<-chan deviceSignal, func()) {
	ch := make(chan deviceSignal, 2)
	h.mu.Lock()
	if h.subscribers[deviceID] == nil {
		h.subscribers[deviceID] = make(map[chan deviceSignal]struct{})
	}
	h.subscribers[deviceID][ch] = struct{}{}
	h.mu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			h.mu.Lock()
			delete(h.subscribers[deviceID], ch)
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
	for ch := range h.subscribers[deviceID] {
		select {
		case ch <- signal:
		default:
			// Signals are edge-triggered hints. One pending wake-up is enough;
			// command state itself remains durable in the database.
		}
	}
}

var deviceSignalHubs sync.Map // map[*Server]*deviceSignalHub

func signalHubFor(server *Server) *deviceSignalHub {
	value, _ := deviceSignalHubs.LoadOrStore(server, newDeviceSignalHub())
	return value.(*deviceSignalHub)
}

// WebSocketManagementHandler adds the outbound-device wake-up channel while
// preserving every existing ManagementHandler route. WebSocket frames never
// contain commands, credentials, configuration, or private key material.
func (s *Server) WebSocketManagementHandler() http.Handler {
	mux := http.NewServeMux()
	wsHandler := s.requestIDMiddleware(s.securityHeaders(http.HandlerFunc(s.deviceWebSocket)))
	mux.Handle("GET /api/v1/device/ws", wsHandler)
	mux.Handle("/", s.deviceCommandSignalMiddleware(s.ManagementHandler()))
	return mux
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
	signals, unsubscribe := signalHubFor(s).subscribe(principal.DeviceID)
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

	keepalive := time.NewTicker(deviceSignalKeepalive)
	defer keepalive.Stop()
	for {
		select {
		case signal := <-signals:
			if err := sendDeviceSignal(conn, signal); err != nil {
				return
			}
			if signal.Type == "reauth_required" {
				return
			}
		case <-keepalive.C:
			if err := sendDeviceSignal(conn, deviceSignal{Type: "keepalive"}); err != nil {
				return
			}
		}
	}
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
