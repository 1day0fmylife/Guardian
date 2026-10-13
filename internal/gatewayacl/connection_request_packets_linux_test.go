//go:build linux

package gatewayacl

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/1day0fmylife/Guardian/internal/store"
)

func TestConnectionRequestPacketServer(t *testing.T) {
	address := os.Getenv("GUARDIAN_CR_SERVER")
	if address == "" {
		t.Skip("isolated packet server")
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, r.RemoteAddr) })}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	defer func() { // Close terminates Serve; its expected closed-server error is cleanup only.
		_ = server.Close()
		<-done
	}()
	if err := os.WriteFile(os.Getenv("GUARDIAN_CR_READY"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	time.Sleep(time.Minute)
}

func TestConnectionRequestPacketClient(t *testing.T) {
	target := os.Getenv("GUARDIAN_CR_TARGET")
	if target == "" {
		t.Skip("isolated packet client")
	}
	local, err := net.ResolveTCPAddr("tcp", os.Getenv("GUARDIAN_CR_CLIENT_SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	dialer := &net.Dialer{Timeout: 400 * time.Millisecond, LocalAddr: local}
	transport := &http.Transport{Proxy: nil, DialContext: dialer.DialContext}
	defer transport.CloseIdleConnections()
	client := &http.Client{Timeout: 600 * time.Millisecond, Transport: transport}
	response, err := client.Get("http://" + target + "/cwmp-connection")
	want := os.Getenv("GUARDIAN_CR_ALLOWED") == "1"
	if (err == nil) != want {
		t.Fatalf("packet request %s permitted=%v, want %v: %v", target, err == nil, want, err)
	}
	if response != nil {
		defer func() { _ = response.Body.Close() }()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatal(err)
		}
		if expected := os.Getenv("GUARDIAN_CR_EXPECT_REMOTE"); expected != "" && !strings.HasPrefix(string(body), expected+":") {
			t.Fatalf("callback observed source=%s, want %s", body, expected)
		}
	}
}

func TestConnectionRequestGatewayPackets(t *testing.T) {
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	parent := os.Getenv("GUARDIAN_CR_PARENT_NETNS")
	if parent == "" || parent == current || os.Geteuid() != 0 {
		t.Skip("explicitly isolated user/network namespace required")
	}
	ctx := context.Background()
	dir := t.TempDir()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v\n%s", name, args, err, out)
		}
		return string(out)
	}
	sleeper := func() *exec.Cmd {
		t.Helper()
		command := exec.Command("unshare", "-n", "sleep", "60")
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
		return command
	}
	peer := sleeper()
	backend := sleeper()
	time.Sleep(50 * time.Millisecond)
	peerPID, backendPID := strconv.Itoa(peer.Process.Pid), strconv.Itoa(backend.Process.Pid)
	run("ip", "link", "set", "lo", "up")
	for _, link := range []struct{ host, remote, pid, local, child string }{{"wg0", "peer0", peerPID, "10.77.0.1/24", "10.77.0.2/24"}, {"eth0", "backend0", backendPID, "172.30.0.1/24", "172.30.0.2/24"}} {
		run("ip", "link", "add", link.host, "type", "veth", "peer", "name", link.remote)
		run("ip", "link", "set", link.remote, "netns", link.pid)
		run("ip", "addr", "add", link.local, "dev", link.host)
		run("ip", "link", "set", link.host, "up")
		run("nsenter", "-t", link.pid, "-n", "ip", "link", "set", "lo", "up")
		run("nsenter", "-t", link.pid, "-n", "ip", "addr", "add", link.child, "dev", link.remote)
		run("nsenter", "-t", link.pid, "-n", "ip", "link", "set", link.remote, "up")
	}
	run("ip", "addr", "add", "10.78.0.12/32", "dev", "lo")
	run("nsenter", "-t", backendPID, "-n", "ip", "route", "add", "10.77.0.0/24", "via", "172.30.0.1")
	run("nsenter", "-t", backendPID, "-n", "ip", "addr", "add", "172.30.0.3/32", "dev", "backend0")
	run("nsenter", "-t", peerPID, "-n", "ip", "route", "add", "default", "via", "10.77.0.1")
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0); err != nil {
		t.Fatal(err)
	}
	startServer := func(pid, name, address string) {
		t.Helper()
		command := exec.Command("nsenter", "-t", pid, "-n", binary, "-test.run", "^TestConnectionRequestPacketServer$")
		command.Env = append(os.Environ(), "GUARDIAN_CR_SERVER="+address, "GUARDIAN_CR_READY="+filepath.Join(dir, name+"-ready"))
		command.Stdout = io.Discard
		command.Stderr = io.Discard
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
		ready := false
		for i := 0; i < 300; i++ {
			if _, err := os.Stat(filepath.Join(dir, name+"-ready")); err == nil {
				ready = true
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if !ready {
			t.Fatal("packet server not ready")
		}
	}
	startServer(peerPID, "peer", "10.77.0.2:7547")
	startServer(backendPID, "backend", "172.30.0.2:8080")
	profile := os.Getenv("GUARDIAN_CR_PROFILE_TEMPLATE")
	if profile == "" {
		profile = "../../deploy/service-gateway/cwmp-cr.nft.tmpl"
	}
	template, err := os.ReadFile(profile)
	if err != nil {
		t.Fatal(err)
	}
	script := strings.NewReplacer("${NFT_TABLE}", "guardian_gw", "${WG_INTERFACE}", "wg0", "${CWMP_CR_BACKEND_INTERFACE}", "eth0", "${CWMP_CR_BACKEND_ADDRESS}", "172.30.0.2", "${VIP_ACS}", "10.78.0.12").Replace(string(template))
	base := `table inet guardian_gw {
 set cwmp_cr_v4 {
  type ipv4_addr
  flags timeout
 }
 chain forward {
  type filter hook forward priority filter
  policy drop
 }
}
`

	apply := func(script string) {
		t.Helper()
		command := exec.Command("nft", "-f", "-")
		command.Stdin = strings.NewReader(script)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("nft callback profile: %v\n%s", err, out)
		}
	}
	apply(base + script)
	check := func(pid, source, target string, allowed bool, expected string) {
		t.Helper()
		command := exec.Command("nsenter", "-t", pid, "-n", binary, "-test.run", "^TestConnectionRequestPacketClient$")
		command.Env = append(os.Environ(), "GUARDIAN_CR_TARGET="+target, "GUARDIAN_CR_CLIENT_SOURCE="+source, fmt.Sprintf("GUARDIAN_CR_ALLOWED=%d", map[bool]int{true: 1, false: 0}[allowed]), "GUARDIAN_CR_EXPECT_REMOTE="+expected)
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("gateway callback probe: %v\n%s", err, out)
		}
	}
	check(backendPID, "172.30.0.2:0", "10.77.0.2:7547", false, "")
	target := store.ServiceAccessTarget{Address: netip.MustParseAddr("10.77.0.2"), ServiceIDs: []string{"sunkarcwmp-acs"}, CWMPConnectionRequestSource: "10.78.0.12"}
	grant, err := RenderConnectionRequests("guardian_gw", "10.78.0.12", []store.ServiceAccessTarget{target})
	if err != nil {
		t.Fatal(err)
	}
	apply(grant)
	check(backendPID, "172.30.0.2:0", "10.77.0.2:7547", true, "10.78.0.12")
	check(backendPID, "172.30.0.3:0", "10.77.0.2:7547", false, "")
	check(backendPID, "172.30.0.2:0", "10.77.0.2:22", false, "")
	check(peerPID, "10.77.0.2:0", "172.30.0.2:8080", false, "")
	revoked, err := RenderConnectionRequests("guardian_gw", "10.78.0.12", nil)
	if err != nil {
		t.Fatal(err)
	}
	apply(revoked)
	check(backendPID, "172.30.0.2:0", "10.77.0.2:7547", false, "")
	t.Log("gateway CR: empty/granted/revoked sets, exact backend, source SNAT, wrong port and peer-to-backend denial passed")
}
