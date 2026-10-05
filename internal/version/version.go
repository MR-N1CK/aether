package version

import (
	"encoding/json"
	"fmt"
	"runtime"
)

// Info holds build, version, and platform metadata.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	YARA      string `json:"yara"`
}

// New returns a new Info struct populated with the provided strings and runtime constants.
func New(ver, commit, buildDate, yaraStatus string) Info {
	return Info{
		Version:   ver,
		Commit:    commit,
		BuildDate: buildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		YARA:      yaraStatus,
	}
}

// String formats the version info as human-readable text block adhering to contracts/cli-version-contract.md.
func (i Info) String() string {
	return fmt.Sprintf("Aether Threat Hunter v%s\n  Commit:     %s\n  Build Date: %s\n  Go Version: %s\n  OS/Arch:    %s/%s\n  YARA:       %s",
		i.Version,
		i.Commit,
		i.BuildDate,
		i.GoVersion,
		i.OS,
		i.Arch,
		i.YARA,
	)
}

// JSON formats the version info as indented JSON.
func (i Info) JSON() (string, error) {
	data, err := json.MarshalIndent(i, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}
