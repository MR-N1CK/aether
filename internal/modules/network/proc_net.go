package network

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// SocketEntry represents a parsed network socket record from /proc/net.
type SocketEntry struct {
	Protocol  string // "tcp", "tcp6", "udp", "udp6", "raw", "raw6", "packet"
	LocalIP   net.IP
	LocalPort int
	RemIP     net.IP
	RemPort   int
	State     string
	StateCode uint8
	UID       uint32
	Inode     uint64
	Owner     *ProcessSocketOwner
}

// TCP state code mapping
var tcpStateMap = map[uint8]string{
	0x01: "ESTABLISHED",
	0x02: "SYN_SENT",
	0x03: "SYN_RECV",
	0x04: "FIN_WAIT1",
	0x05: "FIN_WAIT2",
	0x06: "TIME_WAIT",
	0x07: "CLOSE",
	0x08: "CLOSE_WAIT",
	0x09: "LAST_ACK",
	0x0A: "LISTEN",
	0x0B: "CLOSING",
	0x0C: "NEW_SYN_RECV",
}

// ParseHexIPv4 decodes little-endian 8-hex-character IPv4 strings from /proc/net (e.g. 0100007F -> 127.0.0.1).
func ParseHexIPv4(hexStr string) (net.IP, error) {
	if len(hexStr) != 8 {
		return nil, fmt.Errorf("invalid IPv4 hex length: %d", len(hexStr))
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	// Linux /proc/net prints 32-bit int in host byte order (little endian on x86)
	return net.IPv4(b[3], b[2], b[1], b[0]), nil
}

// ParseHexIPv6 decodes 32-hex-character IPv6 strings from /proc/net formatted as 4 little-endian 32-bit words.
func ParseHexIPv6(hexStr string) (net.IP, error) {
	if len(hexStr) != 32 {
		return nil, fmt.Errorf("invalid IPv6 hex length: %d", len(hexStr))
	}
	raw, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}

	ip := make(net.IP, 16)
	for i := 0; i < 4; i++ {
		word := binary.LittleEndian.Uint32(raw[i*4 : (i+1)*4])
		binary.BigEndian.PutUint32(ip[i*4:(i+1)*4], word)
	}
	return ip, nil
}

// ParseHexPort converts hex port strings (e.g. 9A5F -> 39519) to integer.
func ParseHexPort(hexStr string) (int, error) {
	val, err := strconv.ParseUint(hexStr, 16, 16)
	if err != nil {
		return 0, err
	}
	return int(val), nil
}

// ParseAddressPort parses "hexIP:hexPort" address fields from /proc/net/tcp, tcp6, udp, raw.
func ParseAddressPort(field string, isIPv6 bool) (net.IP, int, error) {
	parts := strings.SplitN(field, ":", 2)
	if len(parts) != 2 {
		return nil, 0, fmt.Errorf("invalid address:port format: %s", field)
	}

	var ip net.IP
	var err error
	if isIPv6 {
		ip, err = ParseHexIPv6(parts[0])
	} else {
		ip, err = ParseHexIPv4(parts[0])
	}
	if err != nil {
		return nil, 0, err
	}

	port, err := ParseHexPort(parts[1])
	if err != nil {
		return nil, 0, err
	}

	return ip, port, nil
}

// ParseInetSocketTable parses /proc/net/tcp, tcp6, udp, udp6, raw, raw6 table files.
func ParseInetSocketTable(proto string, isIPv6 bool, data []byte, socketToProc map[uint64]*ProcessSocketOwner) ([]SocketEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var entries []SocketEntry

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			// Skip header line (sl local_address rem_address st ...)
			continue
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}

		// fields[1] = local_address, fields[2] = rem_address, fields[3] = st, fields[7] = uid, fields[9] = inode
		localIP, localPort, err := ParseAddressPort(fields[1], isIPv6)
		if err != nil {
			continue
		}

		remIP, remPort, err := ParseAddressPort(fields[2], isIPv6)
		if err != nil {
			continue
		}

		stCode64, _ := strconv.ParseUint(fields[3], 16, 8)
		stCode := uint8(stCode64)
		stateName := tcpStateMap[stCode]
		if stateName == "" {
			stateName = fmt.Sprintf("UNKNOWN_0x%02X", stCode)
		}

		uid64, _ := strconv.ParseUint(fields[7], 10, 32)
		inode64, _ := strconv.ParseUint(fields[9], 10, 64)

		entry := SocketEntry{
			Protocol:  proto,
			LocalIP:   localIP,
			LocalPort: localPort,
			RemIP:     remIP,
			RemPort:   remPort,
			State:     stateName,
			StateCode: stCode,
			UID:       uint32(uid64),
			Inode:     inode64,
			Owner:     socketToProc[inode64],
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// ParsePacketSockets parses /proc/net/packet table.
func ParsePacketSockets(data []byte, socketToProc map[uint64]*ProcessSocketOwner) ([]SocketEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	var entries []SocketEntry

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		if lineNum == 1 {
			// Skip header line (sk RefCnt Type Proto Iface R Rmem User Inode)
			continue
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}

		// fields[7] = User (uid), fields[8] = Inode
		uid64, _ := strconv.ParseUint(fields[7], 10, 32)
		inode64, _ := strconv.ParseUint(fields[8], 10, 64)

		entry := SocketEntry{
			Protocol:  "packet",
			State:     "ACTIVE",
			UID:       uint32(uid64),
			Inode:     inode64,
			Owner:     socketToProc[inode64],
		}
		entries = append(entries, entry)
	}

	return entries, scanner.Err()
}

// ParseAllSockets reads and parses all /proc/net socket tables.
func ParseAllSockets(procRoot string, socketToProc map[uint64]*ProcessSocketOwner, logger *slog.Logger) ([]SocketEntry, error) {
	var allSockets []SocketEntry

	baseNet := "/proc/net"
	if procRoot != "" {
		baseNet = filepath.Join(procRoot, "net")
	}

	tables := []struct {
		file   string
		proto  string
		isIPv6 bool
	}{
		{"tcp", "tcp", false},
		{"tcp6", "tcp6", true},
		{"udp", "udp", false},
		{"udp6", "udp6", true},
		{"raw", "raw", false},
		{"raw6", "raw6", true},
	}

	for _, t := range tables {
		path := filepath.Join(baseNet, t.file)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		entries, pErr := ParseInetSocketTable(t.proto, t.isIPv6, data, socketToProc)
		if pErr != nil {
			logger.Debug("error parsing socket table", slog.String("file", path), slog.Any("error", pErr))
			continue
		}
		allSockets = append(allSockets, entries...)
	}

	// Parse /proc/net/packet
	packetPath := filepath.Join(baseNet, "packet")
	if packetData, err := os.ReadFile(packetPath); err == nil {
		packetEntries, pErr := ParsePacketSockets(packetData, socketToProc)
		if pErr == nil {
			allSockets = append(allSockets, packetEntries...)
		}
	}

	return allSockets, nil
}
