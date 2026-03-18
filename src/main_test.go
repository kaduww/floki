package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// resetState restores global variables to a clean baseline before each test.
func resetState() {
	mu.Lock()
	defer mu.Unlock()
	activeCalls = make(map[string]*CallInfo)
	usedPorts = make(map[int]string)
	interfaces = map[string]string{
		"wan": "192.168.0.1",
		"lan": "10.0.0.1",
	}
	portMin = 20000
	portMax = 20010
	nextPort = portMin
	processedCalls = 0
}

// noopIPTables replaces iptables functions with no-ops for unit tests.
func noopIPTables() {
	insertIPTRule = func(callID, uaIP string, uaPort, localPort int, inAddr, outAddr string) error {
		return nil
	}
	removeIPTRule = func(callID string) {}
}

// ---------------------------------------------------------------------------
// validateCallID
// ---------------------------------------------------------------------------

func TestValidateCallID(t *testing.T) {
	valid := []string{
		"abc123",
		"call-id@domain.com",
		"550e8400-e29b-41d4-a716-446655440000",
		"SIP/2.0+foo=bar",
		strings.Repeat("a", 256),
	}
	for _, id := range valid {
		if !validateCallID(id) {
			t.Errorf("expected valid: %q", id)
		}
	}

	invalid := []string{
		"",
		"has space",
		"semi;colon",
		"single'quote",
		"back`tick",
		"pipe|char",
		"amp&ersand",
		"dollar$sign",
		strings.Repeat("a", 257),
	}
	for _, id := range invalid {
		if validateCallID(id) {
			t.Errorf("expected invalid: %q", id)
		}
	}
}

// ---------------------------------------------------------------------------
// iptablesComment
// ---------------------------------------------------------------------------

func TestIptablesComment(t *testing.T) {
	got := iptablesComment("my-call-id")
	want := "floki:my-call-id"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// parseSDP
// ---------------------------------------------------------------------------

const sdpLF = `v=0
o=- 12345 1 IN IP4 192.168.1.10
s=-
c=IN IP4 192.168.1.10
t=0 0
m=audio 10000 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000`

const sdpCRLF = "v=0\r\no=- 12345 1 IN IP4 192.168.1.10\r\ns=-\r\nc=IN IP4 192.168.1.10\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0 8\r\na=rtpmap:0 PCMU/8000"

func TestParseSDP_LF(t *testing.T) {
	result, err := parseSDP(sdpLF)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn := result["connection"].(map[string]string)
	if conn["ip"] != "192.168.1.10" {
		t.Errorf("connection ip: got %q, want %q", conn["ip"], "192.168.1.10")
	}
	media := result["media"].([]map[string]interface{})
	if len(media) != 1 {
		t.Fatalf("expected 1 media, got %d", len(media))
	}
	if media[0]["port"].(int) != 10000 {
		t.Errorf("media port: got %d, want 10000", media[0]["port"].(int))
	}
	if result["line_ending"].(string) != "\n" {
		t.Errorf("expected LF line ending")
	}
}

func TestParseSDP_CRLF(t *testing.T) {
	result, err := parseSDP(sdpCRLF)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result["line_ending"].(string) != "\r\n" {
		t.Errorf("expected CRLF line ending")
	}
	conn := result["connection"].(map[string]string)
	if conn["ip"] != "192.168.1.10" {
		t.Errorf("connection ip: got %q, want %q", conn["ip"], "192.168.1.10")
	}
}

func TestParseSDP_MultipleMedia(t *testing.T) {
	sdp := "v=0\nc=IN IP4 10.0.0.1\nm=audio 5000 RTP/AVP 0\nm=video 5002 RTP/AVP 96"
	result, err := parseSDP(sdp)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	media := result["media"].([]map[string]interface{})
	if len(media) != 2 {
		t.Fatalf("expected 2 media, got %d", len(media))
	}
	if media[0]["port"].(int) != 5000 {
		t.Errorf("audio port: got %d, want 5000", media[0]["port"].(int))
	}
	if media[1]["port"].(int) != 5002 {
		t.Errorf("video port: got %d, want 5002", media[1]["port"].(int))
	}
}

func TestParseSDP_EmptySDP(t *testing.T) {
	result, err := parseSDP("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	conn := result["connection"].(map[string]string)
	if conn["ip"] != "" {
		t.Errorf("expected empty connection ip, got %q", conn["ip"])
	}
	media := result["media"].([]map[string]interface{})
	if len(media) != 0 {
		t.Errorf("expected no media, got %d", len(media))
	}
}

// ---------------------------------------------------------------------------
// writeSDP
// ---------------------------------------------------------------------------

func TestWriteSDP_ReplacesConnectionIP(t *testing.T) {
	result, _ := parseSDP(sdpLF)
	result["connection"].(map[string]string)["ip"] = "10.0.0.99"
	out := writeSDP(result)
	if !strings.Contains(out, "c=IN IP4 10.0.0.99") {
		t.Errorf("expected modified connection IP in output:\n%s", out)
	}
}

func TestWriteSDP_ReplacesMediaPort(t *testing.T) {
	result, _ := parseSDP(sdpLF)
	result["media"].([]map[string]interface{})[0]["port"] = 20001
	out := writeSDP(result)
	if !strings.Contains(out, "m=audio 20001") {
		t.Errorf("expected modified media port in output:\n%s", out)
	}
}

func TestWriteSDP_PreservesOtherLines(t *testing.T) {
	result, _ := parseSDP(sdpLF)
	out := writeSDP(result)
	if !strings.Contains(out, "a=rtpmap:0 PCMU/8000") {
		t.Errorf("expected non-media/connection lines to be preserved:\n%s", out)
	}
}

func TestWriteSDP_PreservesCRLF(t *testing.T) {
	result, _ := parseSDP(sdpCRLF)
	out := writeSDP(result)
	if !strings.Contains(out, "\r\n") {
		t.Errorf("expected CRLF line endings to be preserved")
	}
}

func TestWriteSDP_RoundTrip(t *testing.T) {
	result, _ := parseSDP(sdpLF)
	out := writeSDP(result)
	// All original lines should still be present (order preserved)
	for _, line := range []string{"v=0", "s=-", "t=0 0", "a=rtpmap:0 PCMU/8000"} {
		if !strings.Contains(out, line) {
			t.Errorf("missing line %q in round-trip output", line)
		}
	}
}

// ---------------------------------------------------------------------------
// getNewPort
// ---------------------------------------------------------------------------

func TestGetNewPort_Basic(t *testing.T) {
	resetState()
	port, ok := getNewPort("call-1")
	if !ok {
		t.Fatal("expected port allocation to succeed")
	}
	if port < portMin || port > portMax {
		t.Errorf("port %d out of range [%d, %d]", port, portMin, portMax)
	}
	if usedPorts[port] != "call-1" {
		t.Errorf("port not registered in usedPorts")
	}
}

func TestGetNewPort_Sequential(t *testing.T) {
	resetState()
	ports := make([]int, 5)
	for i := range ports {
		p, ok := getNewPort(fmt.Sprintf("call-%d", i))
		if !ok {
			t.Fatalf("allocation failed at step %d", i)
		}
		ports[i] = p
	}
	// Sequential: each port should be previous + 1
	for i := 1; i < len(ports); i++ {
		if ports[i] != ports[i-1]+1 {
			t.Errorf("expected sequential ports, got %v", ports)
		}
	}
}

func TestGetNewPort_WrapAround(t *testing.T) {
	resetState()
	// Fill all ports except the first one
	for port := portMin + 1; port <= portMax; port++ {
		usedPorts[port] = "other-call"
	}
	nextPort = portMin + 1 // start past the only free port

	port, ok := getNewPort("wrap-call")
	if !ok {
		t.Fatal("expected wrap-around to find the free port")
	}
	if port != portMin {
		t.Errorf("expected wrap to portMin (%d), got %d", portMin, port)
	}
}

func TestGetNewPort_Exhausted(t *testing.T) {
	resetState()
	for port := portMin; port <= portMax; port++ {
		usedPorts[port] = "some-call"
	}
	_, ok := getNewPort("new-call")
	if ok {
		t.Error("expected failure when all ports are used")
	}
}

func TestGetNewPort_NoDuplicates(t *testing.T) {
	resetState()
	seen := make(map[int]bool)
	for i := 0; i < portMax-portMin; i++ {
		p, ok := getNewPort(fmt.Sprintf("call-%d", i))
		if !ok {
			t.Fatalf("unexpected failure at allocation %d", i)
		}
		if seen[p] {
			t.Errorf("duplicate port %d allocated", p)
		}
		seen[p] = true
	}
}

// ---------------------------------------------------------------------------
// handleRequest
// ---------------------------------------------------------------------------

func TestHandleRequest_NewCall(t *testing.T) {
	resetState()
	noopIPTables()

	cmd := &Command{
		CallID:  "test-call-1",
		InIface: "wan",
		OutIface: "lan",
		UAIP:    "1.2.3.4",
		SDP:     sdpLF,
	}
	resp := handleRequest(cmd)

	if resp.Result != 1 {
		t.Fatalf("expected Result=1, got %d (cause: %s)", resp.Result, resp.Cause)
	}
	if resp.SDP == "" {
		t.Error("expected non-empty SDP in response")
	}
	if resp.CallID != "test-call-1" {
		t.Errorf("unexpected CallID in response: %q", resp.CallID)
	}

	mu.RLock()
	defer mu.RUnlock()
	if _, exists := activeCalls["test-call-1"]; !exists {
		t.Error("call not registered in activeCalls")
	}
	if processedCalls != 1 {
		t.Errorf("expected processedCalls=1, got %d", processedCalls)
	}
}

func TestHandleRequest_SDPPortReplaced(t *testing.T) {
	resetState()
	noopIPTables()

	cmd := &Command{
		CallID:   "test-call-2",
		InIface:  "wan",
		OutIface: "lan",
		UAIP:     "1.2.3.4",
		SDP:      sdpLF,
	}
	resp := handleRequest(cmd)

	if resp.Result != 1 {
		t.Fatalf("expected Result=1, got %d", resp.Result)
	}
	// Original port 10000 must not appear; allocated port must be in range
	if strings.Contains(resp.SDP, "m=audio 10000") {
		t.Error("original port 10000 should have been replaced in modified SDP")
	}
}

func TestHandleRequest_ConnectionIPReplaced(t *testing.T) {
	resetState()
	noopIPTables()

	cmd := &Command{
		CallID:   "test-call-3",
		InIface:  "wan",
		OutIface: "lan",
		UAIP:     "1.2.3.4",
		SDP:      sdpLF,
	}
	resp := handleRequest(cmd)

	if resp.Result != 1 {
		t.Fatalf("expected Result=1, got %d", resp.Result)
	}
	// Connection IP must be replaced with the outIface address
	outAddr := interfaces["lan"]
	if !strings.Contains(resp.SDP, "c=IN IP4 "+outAddr) {
		t.Errorf("expected connection IP to be replaced with %q in:\n%s", outAddr, resp.SDP)
	}
}

func TestHandleRequest_InvalidCallID(t *testing.T) {
	resetState()
	noopIPTables()

	cmd := &Command{
		CallID:   "bad call; id",
		InIface:  "wan",
		OutIface: "lan",
		UAIP:     "1.2.3.4",
		SDP:      sdpLF,
	}
	// validateCallID is checked in the NG handler, not in handleRequest directly.
	// Confirm validateCallID rejects it.
	if validateCallID(cmd.CallID) {
		t.Error("expected invalid call ID to be rejected by validateCallID")
	}
}

func TestHandleRequest_IPTablesError(t *testing.T) {
	resetState()
	insertIPTRule = func(callID, uaIP string, uaPort, localPort int, inAddr, outAddr string) error {
		return fmt.Errorf("iptables not available")
	}

	cmd := &Command{
		CallID:   "fail-call",
		InIface:  "wan",
		OutIface: "lan",
		UAIP:     "1.2.3.4",
		SDP:      sdpLF,
	}
	resp := handleRequest(cmd)

	if resp.Result != 0 {
		t.Error("expected Result=0 when iptables insertion fails")
	}
	if resp.Cause == "" {
		t.Error("expected non-empty Cause on iptables failure")
	}
}

func TestHandleRequest_NoPortsAvailable(t *testing.T) {
	resetState()
	noopIPTables()
	// Fill all ports
	for p := portMin; p <= portMax; p++ {
		usedPorts[p] = "other"
	}

	cmd := &Command{
		CallID:   "no-port-call",
		InIface:  "wan",
		OutIface: "lan",
		UAIP:     "1.2.3.4",
		SDP:      sdpLF,
	}
	resp := handleRequest(cmd)

	if resp.Result != 0 {
		t.Error("expected Result=0 when no ports are available")
	}
}

// ---------------------------------------------------------------------------
// handleReply
// ---------------------------------------------------------------------------

func TestHandleReply_NoExistingCall(t *testing.T) {
	resetState()
	noopIPTables()

	cmd := &Command{
		CallID: "nonexistent",
		UAIP:   "5.6.7.8",
		SDP:    sdpLF,
	}
	resp := handleReply(cmd)

	if resp.Result != 0 {
		t.Error("expected Result=0 for answer without a prior offer")
	}
}

func TestHandleReply_AfterOffer(t *testing.T) {
	resetState()
	noopIPTables()

	// First, create the call via offer
	offerCmd := &Command{
		CallID:   "full-call",
		InIface:  "wan",
		OutIface: "lan",
		UAIP:     "1.2.3.4",
		SDP:      sdpLF,
	}
	offerResp := handleRequest(offerCmd)
	if offerResp.Result != 1 {
		t.Fatalf("offer failed: %s", offerResp.Cause)
	}

	// Then answer
	answerCmd := &Command{
		CallID: "full-call",
		UAIP:   "5.6.7.8",
		SDP:    sdpLF,
	}
	resp := handleReply(answerCmd)

	if resp.Result != 1 {
		t.Fatalf("expected Result=1 for answer, got %d (cause: %s)", resp.Result, resp.Cause)
	}
	if resp.SDP == "" {
		t.Error("expected non-empty SDP in answer response")
	}

	mu.RLock()
	defer mu.RUnlock()
	call := activeCalls["full-call"]
	if _, exists := call.Endpoints["5.6.7.8"]; !exists {
		t.Error("callee endpoint not registered after answer")
	}
}

// ---------------------------------------------------------------------------
// loadConfig
// ---------------------------------------------------------------------------

func TestLoadConfig(t *testing.T) {
	content := `
[general]
manager_ip=127.0.0.1
manager_port=3000
rtp_port_min=10000
rtp_port_max=20000
cleanup_on_start=true
log_level=debug

[wan]
ip=1.2.3.4

[lan]
ip=10.0.0.1
`
	f, err := os.CreateTemp("", "floki-test-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	// Reset to defaults
	portMin = 16384
	portMax = 32767
	managerIP = "0.0.0.0"
	managerPort = 2223
	cleanupOnStart = false
	setLogLevel(LogInfo)

	if err := loadConfig(f.Name()); err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}

	if managerIP != "127.0.0.1" {
		t.Errorf("manager_ip: got %q, want %q", managerIP, "127.0.0.1")
	}
	if managerPort != 3000 {
		t.Errorf("manager_port: got %d, want 3000", managerPort)
	}
	if portMin != 10000 {
		t.Errorf("rtp_port_min: got %d, want 10000", portMin)
	}
	if portMax != 20000 {
		t.Errorf("rtp_port_max: got %d, want 20000", portMax)
	}
	if !cleanupOnStart {
		t.Error("expected cleanup_on_start=true")
	}
	if getLogLevel() != LogDebug {
		t.Errorf("expected log_level=debug, got %d", getLogLevel())
	}
	if interfaces["wan"] != "1.2.3.4" {
		t.Errorf("wan interface: got %q, want %q", interfaces["wan"], "1.2.3.4")
	}
	if interfaces["lan"] != "10.0.0.1" {
		t.Errorf("lan interface: got %q, want %q", interfaces["lan"], "10.0.0.1")
	}
}

func TestLoadConfig_NoInterfaces(t *testing.T) {
	content := "[general]\nmanager_port=2223\n"
	f, err := os.CreateTemp("", "floki-test-*.conf")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	if err := loadConfig(f.Name()); err == nil {
		t.Error("expected error when no interfaces are configured")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	if err := loadConfig("/nonexistent/path/floki.conf"); err == nil {
		t.Error("expected error for missing config file")
	}
}
