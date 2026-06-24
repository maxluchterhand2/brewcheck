// Package timeouts centralizes the network and subprocess timeouts used across
// brewcheck, so they can be seen and tuned in one place rather than sprinkled as
// literals throughout the codebase.
package timeouts

import "time"

const (
	// HTTP API clients.
	HomebrewAPI = 30 * time.Second // formulae.brew.sh JSON API
	VirusTotal  = 60 * time.Second // VirusTotal v3 (per request)
	GitHub      = 25 * time.Second // GitHub REST API
	OCIToken    = 15 * time.Second // ghcr.io anonymous pull token

	// brew subprocesses.
	BrewCache = 30 * time.Second  // brew --cache
	BrewInfo  = 120 * time.Second // brew info --json=v2 (may git-clone a tap)

	// External scanner / extraction subprocesses.
	Semgrep  = 3 * time.Minute
	ClamAV   = 5 * time.Minute
	ClamPing = 5 * time.Second // clamdscan --ping (is the daemon up?)
	YARA     = 5 * time.Minute
	Capa     = 3 * time.Minute
	Pkgutil  = 2 * time.Minute
	SevenZip = 5 * time.Minute

	// VTPollInterval is how long to wait between VirusTotal analysis polls.
	VTPollInterval = 15 * time.Second
)
