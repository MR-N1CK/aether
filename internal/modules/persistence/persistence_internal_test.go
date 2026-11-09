package persistence

import "testing"

// TestClassifyMultiVectorPayload pins the payload-strength gate for
// Persistence_Multi_Vector_Persistence. Internal test file: the classifier and
// its helpers are unexported. Regression source: 2026-11 review finding A3 —
// benign user-session tooling in hidden home paths escalated to MALICIOUS.
func TestClassifyMultiVectorPayload(t *testing.T) {
	etcUnit := "/etc" + "/systemd/system/sysupd.service"
	cronRef := "/etc" + "/cron.d/sysupd"
	rcLocalRef := "/etc" + "/rc.local"
	homeUserUnit := "/home/" + "alice/.config/systemd/user/agent.service"
	homeProfile := "/home/" + "alice/.profile"
	homeXdg := "/home/" + "alice/.config/autostart/agent.desktop"
	homeTool := "/home/" + "alice/.local/share/tool/bin/tool"
	homeCache := "/home/" + "alice/.cache/agent"

	cases := []struct {
		name      string
		payload   string
		artMap    map[string]map[string]bool
		isMissing bool
		wantDown  bool
	}{
		{
			name:    "hidden system dir payload stays strong",
			payload: "/usr/lib/.system-cache/.sysupd",
			artMap: map[string]map[string]bool{
				"systemd":  {etcUnit: true},
				"cron":     {cronRef: true},
				"rc.local": {rcLocalRef: true},
			},
			wantDown: false,
		},
		{
			name:    "user-home payload with any system wiring stays strong",
			payload: homeCache,
			artMap: map[string]map[string]bool{
				"systemd":       {etcUnit: true},
				"profile":       {homeProfile: true},
				"xdg_autostart": {homeXdg: true},
			},
			wantDown: false,
		},
		{
			name:    "user-session-only wiring downgrades",
			payload: homeTool,
			artMap: map[string]map[string]bool{
				"systemd":       {homeUserUnit: true},
				"profile":       {homeProfile: true},
				"xdg_autostart": {homeXdg: true},
			},
			wantDown: true,
		},
		{
			name:      "missing payload stays strong even if user-session wired",
			payload:   homeCache,
			artMap:    map[string]map[string]bool{"systemd": {homeUserUnit: true}, "profile": {homeProfile: true}, "xdg_autostart": {homeXdg: true}},
			isMissing: true,
			wantDown:  false,
		},
		{
			name:    "root wiring keeps full strength",
			payload: homeCache,
			artMap: map[string]map[string]bool{
				"profile":       {"/root/.bashrc": true},
				"systemd":       {homeUserUnit: true},
				"xdg_autostart": {homeXdg: true},
			},
			wantDown: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyMultiVectorPayload(tc.payload, tc.artMap, tc.isMissing)
			if got.downgrade != tc.wantDown {
				t.Errorf("classifyMultiVectorPayload(%q, ...) downgrade = %v; want %v (strength: %+v)",
					tc.payload, got.downgrade, tc.wantDown, got)
			}
		})
	}
}
