package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/zeebo/bencode"
	"gopkg.in/ini.v1"
)

/*
Floki is an Iptables Port Forward based RTP relay

Project started on 2021-11-04

Contributors:
        Carlos Eduardo Wagner
            kaduww@gmail.com, carlos@sippulse.com
            https://github.com/kaduww
            https://www.linkedin.com/in/carlos-eduardo-wagner-96bbb433/
*/

// ---------------------------------------------------------------------------
// Log levels
// ---------------------------------------------------------------------------

type LogLevel int

const (
	LogDebug LogLevel = iota
	LogInfo
	LogWarn
	LogError
)

var (
	currentLogLevel  = LogInfo
	logLevelNames    = map[string]LogLevel{"debug": LogDebug, "info": LogInfo, "warn": LogWarn, "error": LogError}
	logLevelPrefixes = map[LogLevel]string{LogDebug: "DEBUG", LogInfo: "INFO", LogWarn: "WARN", LogError: "ERROR"}
)

func logf(level LogLevel, format string, args ...interface{}) {
	if level < currentLogLevel {
		return
	}
	log.Printf("[%s] "+format, append([]interface{}{logLevelPrefixes[level]}, args...)...)
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

var (
	portMin        = 16384
	portMax        = 32767
	managerIP      = "0.0.0.0"
	managerPort    = 2223
	pidFile        = "/var/run/floki.pid"
	cleanupOnStart = false
	activeConfigPath string

	nextPort       = portMin
	activeCalls    = make(map[string]*CallInfo)
	usedPorts      = make(map[int]string)
	interfaces     = make(map[string]string)
	processedCalls = 0
	startEpoch     = time.Now()

	mu sync.RWMutex
)

// ---------------------------------------------------------------------------
// Prometheus metrics
// ---------------------------------------------------------------------------

var (
	metricProcessedCalls = promauto.NewCounter(prometheus.CounterOpts{
		Name: "floki_processed_calls_total",
		Help: "Total number of processed calls",
	})
	metricActiveCalls = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "floki_active_calls",
		Help: "Number of currently active calls",
	})
	metricIptablesErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "floki_iptables_errors_total",
		Help: "Total number of iptables rule insertion/deletion errors",
	})
	metricPortAllocFailures = promauto.NewCounter(prometheus.CounterOpts{
		Name: "floki_port_allocation_failures_total",
		Help: "Total number of port allocation failures",
	})
	metricDeletedCalls = promauto.NewCounter(prometheus.CounterOpts{
		Name: "floki_deleted_calls_total",
		Help: "Total number of deleted/terminated calls",
	})
)

// ---------------------------------------------------------------------------
// Structs
// ---------------------------------------------------------------------------

type CallInfo struct {
	NetInfo            NetInfo                  `json:"net_info"`
	Endpoints          map[string]*EndpointInfo `json:"endpoints,omitempty"`
	LocalUsedPorts     []int                    `json:"local_used_ports"`
	LastRequestSDPRecv string                   `json:"last_request_sdp_received,omitempty"`
	LastRequestSDPMod  string                   `json:"last_request_sdp_modified,omitempty"`
	LastReplySDPRecv   string                   `json:"last_reply_sdp_received,omitempty"`
	LastReplySDPMod    string                   `json:"last_reply_sdp_modified,omitempty"`
}

type NetInfo struct {
	InAddr  string `json:"in_addr"`
	OutAddr string `json:"out_addr"`
}

type EndpointInfo struct {
	LocalOutAddr string      `json:"local_out_addr"`
	MediaList    []MediaInfo `json:"media_list"`
}

type MediaInfo struct {
	UAPort    int `json:"ua_port"`
	LocalPort int `json:"local_port"`
}

type Command struct {
	CallID   string
	InIface  string
	OutIface string
	UAIP     string
	Natted   bool
	SDP      string
}

type Response struct {
	Result int    `json:"Result"`
	CallID string `json:"call_uuid,omitempty"`
	SDP    string `json:"sdp,omitempty"`
	Cause  string `json:"Cause,omitempty"`
}

// ---------------------------------------------------------------------------
// CallID validation — prevents shell/iptables comment injection
// ---------------------------------------------------------------------------

var validCallID = regexp.MustCompile(`^[a-zA-Z0-9@._:+/=\-]{1,256}$`)

func validateCallID(id string) bool {
	return id != "" && validCallID.MatchString(id)
}

// ---------------------------------------------------------------------------
// Port allocation — sequential with wrap-around (no busy-loop)
// Caller MUST hold mu write lock.
// ---------------------------------------------------------------------------

func getNewPort(callID string) (int, bool) {
	if len(usedPorts) >= portMax-portMin+1 {
		metricPortAllocFailures.Inc()
		return 0, false
	}
	start := nextPort
	for {
		port := nextPort
		nextPort++
		if nextPort > portMax {
			nextPort = portMin
		}
		if _, used := usedPorts[port]; !used {
			usedPorts[port] = callID
			return port, true
		}
		if nextPort == start {
			metricPortAllocFailures.Inc()
			return 0, false
		}
	}
}

// ---------------------------------------------------------------------------
// iptables — direct exec.Command args (no shell interpolation)
// ---------------------------------------------------------------------------

// iptablesComment returns the comment tag embedded in iptables rules.
func iptablesComment(callID string) string {
	return "floki:" + callID
}

// insertIPTRule inserts DNAT+SNAT rules for an RTP stream.
// Defined as a variable to allow mocking in tests.
var insertIPTRule = func(callID, uaIP string, uaPort, localPort int, inAddr, outAddr string) error {
	comment := iptablesComment(callID)

	// PREROUTING — DNAT: packets arriving on outAddr:localPort → uaIP:uaPort
	preArgs := []string{
		"-t", "nat", "-I", "PREROUTING",
		"-d", outAddr + "/32",
		"-p", "udp", "--dport", strconv.Itoa(localPort),
		"-m", "comment", "--comment", comment,
		"-j", "DNAT", "--to-destination", fmt.Sprintf("%s:%d", uaIP, uaPort),
	}
	if out, err := exec.Command("iptables", preArgs...).CombinedOutput(); err != nil {
		metricIptablesErrors.Inc()
		return fmt.Errorf("PREROUTING rule failed: %v — %s", err, strings.TrimSpace(string(out)))
	}

	// POSTROUTING — SNAT: packets going to uaIP:uaPort sourced from inAddr
	postArgs := []string{
		"-t", "nat", "-I", "POSTROUTING",
		"-d", uaIP + "/32",
		"-p", "udp", "--dport", strconv.Itoa(uaPort),
		"-m", "comment", "--comment", comment,
		"-j", "SNAT", "--to-source", inAddr,
	}
	if out, err := exec.Command("iptables", postArgs...).CombinedOutput(); err != nil {
		metricIptablesErrors.Inc()
		return fmt.Errorf("POSTROUTING rule failed: %v — %s", err, strings.TrimSpace(string(out)))
	}

	logf(LogDebug, "Inserted iptables rules for call %s: %s:%d → %s:%d", callID, outAddr, localPort, uaIP, uaPort)
	return nil
}

// removeIPTRule deletes all iptables rules matching the call's comment tag.
// Defined as a variable to allow mocking in tests.
var removeIPTRule = func(callID string) {
	comment := iptablesComment(callID)
	for _, chain := range []string{"PREROUTING", "POSTROUTING"} {
		for {
			out, err := exec.Command("sh", "-c",
				fmt.Sprintf("iptables -t nat -L %s -n --line-numbers | grep '%s' | awk '{print $1}' | head -1", chain, comment),
			).Output()
			if err != nil || strings.TrimSpace(string(out)) == "" {
				break
			}
			lineNum := strings.TrimSpace(string(out))
			if delOut, delErr := exec.Command("sh", "-c",
				fmt.Sprintf("iptables -t nat -D %s %s", chain, lineNum),
			).CombinedOutput(); delErr != nil {
				logf(LogWarn, "Failed to delete rule from %s line %s: %v — %s", chain, lineNum, delErr, strings.TrimSpace(string(delOut)))
				break
			}
		}
	}
}

// cleanupOrphanedRules removes all floki-owned iptables rules (called on startup when enabled).
func cleanupOrphanedRules() {
	logf(LogInfo, "Cleaning up orphaned iptables rules...")
	for _, chain := range []string{"PREROUTING", "POSTROUTING"} {
		for {
			out, err := exec.Command("sh", "-c",
				fmt.Sprintf("iptables -t nat -L %s -n --line-numbers | grep 'floki:' | awk '{print $1}' | head -1", chain),
			).Output()
			if err != nil || strings.TrimSpace(string(out)) == "" {
				break
			}
			lineNum := strings.TrimSpace(string(out))
			exec.Command("sh", "-c", fmt.Sprintf("iptables -t nat -D %s %s", chain, lineNum)).Run()
		}
		logf(LogInfo, "Chain %s cleaned", chain)
	}
}

// ---------------------------------------------------------------------------
// SDP parser — handles both LF and CRLF line endings
// ---------------------------------------------------------------------------

func parseSDP(sdp string) (map[string]interface{}, error) {
	lineEnding := "\n"
	if strings.Contains(sdp, "\r\n") {
		lineEnding = "\r\n"
	}

	connection := make(map[string]string)
	var media []map[string]interface{}

	for _, line := range strings.Split(sdp, lineEnding) {
		line = strings.TrimSpace(line)
		if len(line) < 2 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "c="):
			parts := strings.Fields(line[2:])
			if len(parts) >= 3 {
				connection["ip"] = parts[2]
			}
		case strings.HasPrefix(line, "m="):
			parts := strings.Fields(line[2:])
			if len(parts) >= 2 {
				port, _ := strconv.Atoi(parts[1])
				media = append(media, map[string]interface{}{
					"type": parts[0],
					"port": port,
					"line": line,
				})
			}
		}
	}

	return map[string]interface{}{
		"connection":   connection,
		"media":        media,
		"raw":          sdp,
		"line_ending":  lineEnding,
	}, nil
}

// writeSDP reconstructs the SDP string, replacing only c= and m= values.
func writeSDP(sdpMap map[string]interface{}) string {
	raw := sdpMap["raw"].(string)
	lineEnding := sdpMap["line_ending"].(string)
	connection := sdpMap["connection"].(map[string]string)
	media := sdpMap["media"].([]map[string]interface{})
	mediaIdx := 0

	var output []string
	for _, line := range strings.Split(raw, lineEnding) {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "c=") && connection["ip"] != "":
			parts := strings.Fields(trimmed[2:])
			if len(parts) >= 3 {
				parts[2] = connection["ip"]
				output = append(output, "c="+strings.Join(parts, " "))
			} else {
				output = append(output, trimmed)
			}
		case strings.HasPrefix(trimmed, "m=") && mediaIdx < len(media):
			parts := strings.Fields(trimmed[2:])
			if len(parts) >= 2 {
				parts[1] = strconv.Itoa(media[mediaIdx]["port"].(int))
				output = append(output, "m="+strings.Join(parts, " "))
				mediaIdx++
			} else {
				output = append(output, trimmed)
			}
		default:
			output = append(output, trimmed)
		}
	}
	return strings.Join(output, lineEnding)
}

// ---------------------------------------------------------------------------
// Call handlers
// ---------------------------------------------------------------------------

// pendingIPTRule holds iptables rule parameters collected under the lock,
// to be executed after the lock is released.
type pendingIPTRule struct {
	uaIP      string
	uaPort    int
	localPort int
	inAddr    string
	outAddr   string
}

// rollbackCall removes call state and allocated ports under the lock.
// Must be called without holding mu.
func rollbackCall(callID string) {
	mu.Lock()
	if callInfo, exists := activeCalls[callID]; exists {
		for _, p := range callInfo.LocalUsedPorts {
			delete(usedPorts, p)
		}
		delete(activeCalls, callID)
		processedCalls--
		metricActiveCalls.Dec()
	}
	mu.Unlock()
	removeIPTRule(callID)
}

// handleRequest processes offer commands.
// State is committed inside the lock; iptables rules are inserted after
// releasing it, allowing concurrent call setups.
func handleRequest(cmd *Command) Response {
	sdpDict, err := parseSDP(cmd.SDP)
	if err != nil {
		return Response{Result: 0, CallID: cmd.CallID, Cause: "Failed to parse SDP"}
	}

	var pending []pendingIPTRule
	var modifiedSDP string
	newCall := false

	mu.Lock()
	if _, exists := activeCalls[cmd.CallID]; !exists {
		newCall = true
		processedCalls++
		metricProcessedCalls.Inc()
		metricActiveCalls.Inc()

		inAddr := interfaces[cmd.InIface]
		outAddr := interfaces[cmd.OutIface]

		connection := sdpDict["connection"].(map[string]string)
		var dstIP string
		if cmd.Natted {
			dstIP = cmd.UAIP
		} else {
			dstIP = connection["ip"]
		}
		connection["ip"] = outAddr

		var mediaList []MediaInfo
		var localUsedPorts []int
		for i, m := range sdpDict["media"].([]map[string]interface{}) {
			uaPort := m["port"].(int)
			localPort, ok := getNewPort(cmd.CallID)
			if !ok {
				for _, p := range localUsedPorts {
					delete(usedPorts, p)
				}
				processedCalls--
				metricActiveCalls.Dec()
				mu.Unlock()
				return Response{Result: 0, CallID: cmd.CallID, Cause: "No more ports available"}
			}
			localUsedPorts = append(localUsedPorts, localPort)
			mediaList = append(mediaList, MediaInfo{UAPort: uaPort, LocalPort: localPort})
			sdpDict["media"].([]map[string]interface{})[i]["port"] = localPort
			pending = append(pending, pendingIPTRule{
				uaIP: dstIP, uaPort: uaPort, localPort: localPort,
				inAddr: inAddr, outAddr: outAddr,
			})
		}

		modifiedSDP = writeSDP(sdpDict)
		activeCalls[cmd.CallID] = &CallInfo{
			NetInfo:            NetInfo{InAddr: inAddr, OutAddr: outAddr},
			Endpoints:          map[string]*EndpointInfo{cmd.UAIP: {LocalOutAddr: outAddr, MediaList: mediaList}},
			LocalUsedPorts:     localUsedPorts,
			LastRequestSDPRecv: cmd.SDP,
			LastRequestSDPMod:  modifiedSDP,
		}
	} else {
		// Re-offer (e.g. re-INVITE) — no new iptables rules needed
		callInfo := activeCalls[cmd.CallID]
		endpointInfo := callInfo.Endpoints[cmd.UAIP]
		connection := sdpDict["connection"].(map[string]string)
		connection["ip"] = endpointInfo.LocalOutAddr
		for i, m := range sdpDict["media"].([]map[string]interface{}) {
			uaPort := m["port"].(int)
			for _, mi := range endpointInfo.MediaList {
				if mi.UAPort == uaPort {
					sdpDict["media"].([]map[string]interface{})[i]["port"] = mi.LocalPort
					break
				}
			}
		}
		modifiedSDP = writeSDP(sdpDict)
		callInfo.LastRequestSDPRecv = cmd.SDP
		callInfo.LastRequestSDPMod = modifiedSDP
	}
	mu.Unlock()

	// Insert iptables rules outside the lock — concurrent with other call setups
	if newCall {
		for _, r := range pending {
			if err := insertIPTRule(cmd.CallID, r.uaIP, r.uaPort, r.localPort, r.inAddr, r.outAddr); err != nil {
				logf(LogError, "iptables insertion failed for call %s: %v", cmd.CallID, err)
				rollbackCall(cmd.CallID)
				return Response{Result: 0, CallID: cmd.CallID, Cause: "Failed to insert iptables rule: " + err.Error()}
			}
		}
	}

	return Response{Result: 1, CallID: cmd.CallID, SDP: modifiedSDP}
}

// handleReply processes answer commands.
func handleReply(cmd *Command) Response {
	sdpDict, err := parseSDP(cmd.SDP)
	if err != nil {
		return Response{Result: 0, CallID: cmd.CallID, Cause: "Failed to parse SDP"}
	}

	var pending []pendingIPTRule
	var modifiedSDP string
	newEndpoint := false

	mu.Lock()
	callInfo, exists := activeCalls[cmd.CallID]
	if !exists {
		mu.Unlock()
		return Response{Result: 0, Cause: "No request command for the uuid"}
	}

	if _, exists := callInfo.Endpoints[cmd.UAIP]; !exists {
		newEndpoint = true
		outAddr := callInfo.NetInfo.InAddr
		inAddr := callInfo.NetInfo.OutAddr

		connection := sdpDict["connection"].(map[string]string)
		var dstIP string
		if cmd.Natted {
			dstIP = cmd.UAIP
		} else {
			dstIP = connection["ip"]
		}
		connection["ip"] = outAddr

		var mediaList []MediaInfo
		var localUsedPorts []int
		for i, m := range sdpDict["media"].([]map[string]interface{}) {
			uaPort := m["port"].(int)
			localPort, ok := getNewPort(cmd.CallID)
			if !ok {
				for _, p := range localUsedPorts {
					delete(usedPorts, p)
				}
				mu.Unlock()
				return Response{Result: 0, CallID: cmd.CallID, Cause: "No more ports available"}
			}
			localUsedPorts = append(localUsedPorts, localPort)
			mediaList = append(mediaList, MediaInfo{UAPort: uaPort, LocalPort: localPort})
			sdpDict["media"].([]map[string]interface{})[i]["port"] = localPort
			pending = append(pending, pendingIPTRule{
				uaIP: dstIP, uaPort: uaPort, localPort: localPort,
				inAddr: inAddr, outAddr: outAddr,
			})
		}

		modifiedSDP = writeSDP(sdpDict)
		callInfo.Endpoints[cmd.UAIP] = &EndpointInfo{LocalOutAddr: outAddr, MediaList: mediaList}
		callInfo.LocalUsedPorts = append(callInfo.LocalUsedPorts, localUsedPorts...)
		callInfo.LastReplySDPRecv = cmd.SDP
		callInfo.LastReplySDPMod = modifiedSDP
	} else {
		// Re-answer — no new iptables rules needed
		endpointInfo := callInfo.Endpoints[cmd.UAIP]
		connection := sdpDict["connection"].(map[string]string)
		connection["ip"] = endpointInfo.LocalOutAddr
		for i, m := range sdpDict["media"].([]map[string]interface{}) {
			uaPort := m["port"].(int)
			for _, mi := range endpointInfo.MediaList {
				if mi.UAPort == uaPort {
					sdpDict["media"].([]map[string]interface{})[i]["port"] = mi.LocalPort
					break
				}
			}
		}
		modifiedSDP = writeSDP(sdpDict)
		callInfo.LastReplySDPRecv = cmd.SDP
		callInfo.LastReplySDPMod = modifiedSDP
	}
	mu.Unlock()

	// Insert iptables rules outside the lock — concurrent with other call setups
	if newEndpoint {
		for _, r := range pending {
			if err := insertIPTRule(cmd.CallID, r.uaIP, r.uaPort, r.localPort, r.inAddr, r.outAddr); err != nil {
				logf(LogError, "iptables insertion failed for call %s (answer): %v", cmd.CallID, err)
				rollbackCall(cmd.CallID)
				return Response{Result: 0, CallID: cmd.CallID, Cause: "Failed to insert iptables rule: " + err.Error()}
			}
		}
	}

	return Response{Result: 1, CallID: cmd.CallID, SDP: modifiedSDP}
}

// ---------------------------------------------------------------------------
// NG Protocol handler
// ---------------------------------------------------------------------------

func handleRTPECommands(data []byte, conn *net.UDPConn, addr *net.UDPAddr) {
	message := string(data)
	parts := strings.SplitN(message, " ", 2)
	if len(parts) < 2 {
		return
	}

	cookie := parts[0]
	encodedCommand := parts[1] + "e"

	var command map[string]interface{}
	if err := bencode.DecodeString(encodedCommand, &command); err != nil {
		logf(LogWarn, "Failed to decode bencode from %s: %v", addr, err)
		return
	}

	reply := make(map[string]interface{})
	cmdType, ok := command["command"].(string)
	if !ok {
		return
	}

	switch cmdType {
	case "ping":
		reply["result"] = "pong"

	case "offer":
		callID, _ := command["call-id"].(string)
		if !validateCallID(callID) {
			reply["result"] = "error"
			reply["reason"] = "invalid call-id"
			break
		}
		sdp, _ := command["sdp"].(string)

		cmd := &Command{CallID: callID, SDP: sdp}

		if direction, ok := command["direction"].([]interface{}); ok && len(direction) >= 2 {
			cmd.InIface, _ = direction[0].(string)
			cmd.OutIface, _ = direction[1].(string)
		} else {
			for iface := range interfaces {
				cmd.InIface = iface
				cmd.OutIface = iface
				break
			}
		}

		if receivedFrom, ok := command["received-from"].([]interface{}); ok && len(receivedFrom) >= 2 {
			cmd.UAIP, _ = receivedFrom[1].(string)
		}

		if flags, ok := command["flags"].([]interface{}); ok {
			for _, flag := range flags {
				if f, ok := flag.(string); ok && f == "SIP-source-address" {
					cmd.Natted = true
					break
				}
			}
		}

		resp := handleRequest(cmd)
		if resp.Result == 1 {
			reply["result"] = "ok"
			reply["sdp"] = resp.SDP
		} else {
			reply["result"] = "error"
			reply["reason"] = resp.Cause
		}

	case "answer":
		callID, _ := command["call-id"].(string)
		if !validateCallID(callID) {
			reply["result"] = "error"
			reply["reason"] = "invalid call-id"
			break
		}
		sdp, _ := command["sdp"].(string)

		cmd := &Command{CallID: callID, SDP: sdp}

		if receivedFrom, ok := command["received-from"].([]interface{}); ok && len(receivedFrom) >= 2 {
			cmd.UAIP, _ = receivedFrom[1].(string)
		}

		if flags, ok := command["flags"].([]interface{}); ok {
			for _, flag := range flags {
				if f, ok := flag.(string); ok && f == "SIP-source-address" {
					cmd.Natted = true
					break
				}
			}
		}

		resp := handleReply(cmd)
		if resp.Result == 1 {
			reply["result"] = "ok"
			reply["sdp"] = resp.SDP
		} else {
			reply["result"] = "error"
			reply["reason"] = resp.Cause
		}

	case "delete":
		callID, _ := command["call-id"].(string)
		if !validateCallID(callID) {
			reply["result"] = "error"
			reply["reason"] = "invalid call-id"
			break
		}

		mu.Lock()
		if callInfo, exists := activeCalls[callID]; exists {
			for _, port := range callInfo.LocalUsedPorts {
				delete(usedPorts, port)
			}
			delete(activeCalls, callID)
			metricActiveCalls.Dec()
			metricDeletedCalls.Inc()
		}
		mu.Unlock()

		removeIPTRule(callID)
		reply["result"] = "ok"
	}

	replyBytes, err := bencode.EncodeString(reply)
	if err != nil {
		logf(LogError, "Failed to encode reply: %v", err)
		return
	}
	conn.WriteToUDP([]byte(cookie+" "+replyBytes), addr)
}

// ---------------------------------------------------------------------------
// Servers
// ---------------------------------------------------------------------------

func startUDPServer() {
	addr := net.UDPAddr{Port: managerPort, IP: net.ParseIP(managerIP)}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Fatalf("[ERROR] Failed to start UDP server: %v", err)
	}
	defer conn.Close()

	logf(LogInfo, "UDP server listening on %s:%d", managerIP, managerPort)

	buffer := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logf(LogWarn, "Error reading UDP: %v", err)
			continue
		}
		data := make([]byte, n)
		copy(data, buffer[:n])
		go handleRTPECommands(data, conn, addr)
	}
}

func startHTTPServer() {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()

	router.GET("/list_calls", func(c *gin.Context) {
		mu.RLock()
		defer mu.RUnlock()
		c.JSON(http.StatusOK, activeCalls)
	})

	router.GET("/status", func(c *gin.Context) {
		mu.RLock()
		defer mu.RUnlock()
		c.JSON(http.StatusOK, gin.H{
			"start_epoch":         int(startEpoch.Unix()),
			"uptime_sec":          int(time.Since(startEpoch).Seconds()),
			"processed_calls":     processedCalls,
			"active_calls":        len(activeCalls),
			"rtp_port_range_size": portMax - portMin,
			"rtp_used_ports":      len(usedPorts),
			"rtp_available_ports": portMax - portMin - len(usedPorts),
			"rtp_port_min":        portMin,
			"rtp_port_max":        portMax,
			"rtp_interfaces":      interfaces,
		})
	})

	// Prometheus metrics endpoint
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))

	addr := fmt.Sprintf("%s:%d", managerIP, managerPort+1)
	logf(LogInfo, "HTTP server listening on %s", addr)

	if err := router.Run(addr); err != nil {
		log.Fatalf("[ERROR] Failed to start HTTP server: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

func loadConfig(path string) error {
	cfg, err := ini.Load(path)
	if err != nil {
		return err
	}

	if cfg.HasSection("general") {
		g := cfg.Section("general")
		if g.HasKey("rtp_port_min") {
			portMin, _ = g.Key("rtp_port_min").Int()
		}
		if g.HasKey("rtp_port_max") {
			portMax, _ = g.Key("rtp_port_max").Int()
		}
		if g.HasKey("manager_ip") {
			managerIP = g.Key("manager_ip").String()
		}
		if g.HasKey("manager_port") {
			managerPort, _ = g.Key("manager_port").Int()
		}
		if g.HasKey("cleanup_on_start") {
			cleanupOnStart, _ = g.Key("cleanup_on_start").Bool()
		}
		if g.HasKey("log_level") {
			lvlStr := strings.ToLower(g.Key("log_level").String())
			if lvl, ok := logLevelNames[lvlStr]; ok {
				currentLogLevel = lvl
			}
		}
	}

	// Reload interfaces (lock needed if called after startup via SIGHUP)
	mu.Lock()
	interfaces = make(map[string]string)
	for _, section := range cfg.Sections() {
		name := section.Name()
		if name != "DEFAULT" && name != "general" && section.HasKey("ip") {
			interfaces[name] = section.Key("ip").String()
		}
	}
	mu.Unlock()

	if len(interfaces) == 0 {
		return fmt.Errorf("no interface configuration found")
	}
	return nil
}

// ---------------------------------------------------------------------------
// PID file
// ---------------------------------------------------------------------------

func writePIDFile(path string) error {
	return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())), 0644)
}

func removePIDFile(path string) {
	os.Remove(path)
}

func checkPIDFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return nil
	}
	if process.Signal(os.Signal(nil)) == nil {
		return fmt.Errorf("floki is already running with PID %d", pid)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Graceful shutdown — cleans up iptables rules for all active calls
// ---------------------------------------------------------------------------

func setupSignalHandlers(cfgPath *string) {
	// SIGTERM / SIGINT — graceful shutdown
	shutdownCh := make(chan os.Signal, 1)
	signal.Notify(shutdownCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-shutdownCh
		logf(LogInfo, "Received signal %v, shutting down...", sig)

		mu.Lock()
		callIDs := make([]string, 0, len(activeCalls))
		for id, callInfo := range activeCalls {
			for _, port := range callInfo.LocalUsedPorts {
				delete(usedPorts, port)
			}
			callIDs = append(callIDs, id)
		}
		activeCalls = make(map[string]*CallInfo)
		mu.Unlock()

		for _, id := range callIDs {
			removeIPTRule(id)
		}
		logf(LogInfo, "Cleaned up %d active call(s). Goodbye.", len(callIDs))
		removePIDFile(pidFile)
		os.Exit(0)
	}()

	// SIGHUP — reload configuration
	sighupCh := make(chan os.Signal, 1)
	signal.Notify(sighupCh, syscall.SIGHUP)
	go func() {
		for range sighupCh {
			logf(LogInfo, "Received SIGHUP, reloading configuration from %s...", *cfgPath)
			if err := loadConfig(*cfgPath); err != nil {
				logf(LogError, "Failed to reload config: %v", err)
			} else {
				logf(LogInfo, "Configuration reloaded. Interfaces: %v", interfaces)
			}
		}
	}()
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	cfgPath := flag.String("config", "/etc/floki/floki.conf", "Path to configuration file")
	flag.Parse()

	if err := loadConfig(*cfgPath); err != nil {
		log.Fatalf("[ERROR] Failed to load configuration: %v", err)
	}
	activeConfigPath = *cfgPath

	if cleanupOnStart {
		cleanupOrphanedRules()
	}

	if err := checkPIDFile(pidFile); err != nil {
		log.Fatal(err)
	}
	if err := writePIDFile(pidFile); err != nil {
		log.Fatalf("[ERROR] Failed to write PID file: %v", err)
	}
	defer removePIDFile(pidFile)

	setupSignalHandlers(cfgPath)

	logf(LogInfo, "Floki RTP Relay starting...")
	logf(LogInfo, "Port range: %d-%d", portMin, portMax)
	logf(LogInfo, "Interfaces: %v", interfaces)
	logf(LogInfo, "Log level: %s", logLevelPrefixes[currentLogLevel])

	go startHTTPServer()
	startUDPServer()
}
