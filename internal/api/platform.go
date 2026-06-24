package api

import (
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// macOS major version -> Homebrew codename. Extend as new releases ship.
var macCodenames = map[int]string{
	27: "golden_gate",
	26: "tahoe",
	15: "sequoia",
	14: "sonoma",
	13: "ventura",
	12: "monterey",
	11: "big_sur",
}

// HostPlatform returns the Homebrew bottle key for the current host, e.g.
// "arm64_tahoe" or "sonoma". It shells out to `sw_vers` only to read the OS
// version (a read-only query), never to brew.
func HostPlatform() (string, error) {
	if runtime.GOOS != "darwin" {
		// Linux bottle keys are arch_linux style.
		switch runtime.GOARCH {
		case "arm64":
			return "arm64_linux", nil
		default:
			return "x86_64_linux", nil
		}
	}
	out, err := exec.Command("sw_vers", "-productVersion").Output()
	if err != nil {
		return "", fmt.Errorf("reading macOS version: %w", err)
	}
	major := 0
	if parts := strings.SplitN(strings.TrimSpace(string(out)), ".", 2); len(parts) > 0 {
		major, _ = strconv.Atoi(parts[0])
	}
	codename, ok := macCodenames[major]
	if !ok {
		return "", fmt.Errorf("unmapped macOS major version %d; update api.macCodenames", major)
	}
	if runtime.GOARCH == "arm64" {
		return "arm64_" + codename, nil
	}
	return codename, nil
}

// SelectBottle picks the bottle file for the given platform key, falling back
// to a platform-independent "all" bottle if present. It returns the chosen key
// so the caller can report exactly what was selected.
func (f *Formula) SelectBottle(platform string) (key string, bf BottleFile, err error) {
	files := f.Bottle.Stable.Files
	if len(files) == 0 {
		return "", BottleFile{}, fmt.Errorf("formula %s has no stable bottle", f.Name)
	}
	if bf, ok := files[platform]; ok {
		return platform, bf, nil
	}
	if bf, ok := files["all"]; ok {
		return "all", bf, nil
	}
	keys := make([]string, 0, len(files))
	for k := range files {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return "", BottleFile{}, fmt.Errorf("no bottle for platform %q (available: %s)", platform, strings.Join(keys, ", "))
}
