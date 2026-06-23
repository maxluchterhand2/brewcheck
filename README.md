# brewcheck

`brewcheck` fetches a Homebrew **formula bottle** or **cask** artifact *without
using the `brew` binary to download it*, verifies its sha256 against Homebrew's
published hash, scans the verified bytes for malware and suspicious patterns,
and — **only on a clean verdict** — hands the bytes to Homebrew's cache so a
later `brew install` skips the download.

> **What this tool is — and isn't.** brewcheck detects **known malware and
> suspicious patterns**. It is **not** a defense against a novel, targeted
> supply-chain attack. Its most valuable output is showing you *what an install
> script actually does*. The strongest claim it will ever make is "No
> known-malicious indicators found" — never "safe".

## Core principle: unverified bytes are radioactive

Nothing untrusted ever touches brew's cache, gets mounted, or gets executed
before it has been verified and scanned:

1. **Download** into an isolated, `0700` quarantine dir brew knows nothing about.
2. **Verify** sha256 against Homebrew's published hash *before anything else*.
   Mismatch → abort, delete, report `HASH_MISMATCH` (no scan, no cache).
3. **Scan** the verified bytes — preferring extraction over mounting/executing.
4. **Cache** the bytes (at the path `brew --cache` reports) on a `CLEAN` or
   `HESITANT` verdict with a verified hash.
5. **Delete** the quarantined bytes on a `SUSPICIOUS`/`MALICIOUS`/`ERROR` verdict.

The sha256 check is load-bearing twice: it proves the scanned bytes are
byte-identical to what brew will install, and it closes the TOCTOU window —
brew re-verifies the cache file's hash at install time, so cached bytes are only
used because they still match.

## Install / build

```sh
go build -o brewcheck .
```

Requires Go (current stable). The only third-party dependency is
`spf13/cobra`.

## Usage

```sh
brewcheck --formula <name>      # check a formula bottle (from ghcr.io)
brewcheck --cask <name>         # check a cask (direct vendor/GitHub URL)
brewcheck <name>                # auto-resolve type (errors if ambiguous)
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--formula <name>` / `--cask <name>` | — | explicit type (mutually exclusive) |
| `--cache` / `--no-cache` | `true` | place verified bytes in brew's cache on a clean verdict |
| `--keep` | `false` | keep the quarantine dir (debugging) |
| `--cloud` | `false` | allow opt-in VirusTotal **file upload** as a last resort |
| `--max-upload-size <bytes>` | `52428800` (50 MiB) | never cloud-upload above this, even with `--cloud` |
| `--json` | `false` | emit a machine-readable JSON report |
| `--verbose` / `-v` | `false` | log each pipeline step to stderr |
| `--quarantine-dir <path>` | OS temp | override the quarantine location |

### Exit codes

| Code | Verdict | Cached? |
|------|---------|---------|
| `0` | `CLEAN` | yes (verified hash) |
| `1` | `SUSPICIOUS` | no |
| `2` | `MALICIOUS` | no (bytes deleted) |
| `3` | `ERROR` | no |
| `4` | `HESITANT` | yes (verified hash) — but with a `⚑` warning to double-check |

`HESITANT` is a soft warning: an intentionally aggressive heuristic (e.g. a YARA
rule tagged `severity = "hesitant"`) fired, but nothing known-malicious was
found. The bytes are **kept and cached** like `CLEAN`; the report just points
you at the flagged item so you can eyeball it before `brew install`. Exit `4` is
an extension to the spec's `0–3` so existing `0/1/2/3` tooling is unaffected.

## Inspection layers

Layers run lead-with-zero-upload, escalate to local heavy scanning, and treat
cloud upload as an opt-in last resort. Findings from every layer that runs are
aggregated into one verdict; a definitive known-bad hit short-circuits.

1. **VirusTotal hash reputation** — `GET /files/{sha256}`, zero bytes uploaded.
   Needs `VT_API_KEY`.
2. **Static analysis (local)** — the highest-value layer. Parses the
   definition JSON and any extracted install scripts, surfacing *what the
   install does* (cask `uninstall`/`zap`/`pkg` stanzas, pkg `pre/postinstall`
   scripts) and flagging risky patterns (`curl|bash`, `base64|sh`,
   LaunchAgents, reverse shells, `eval`, obfuscation). Pure Go, no dependency.
3. **Semgrep** (`brew install semgrep`) — curated Ruby/shell rules in
   `rules/semgrep/` covering RCE, privilege escalation, persistence, exfiltration
   and obfuscation. Severity tiers: `ERROR`/`WARNING` → `SUSPICIOUS`,
   `INFO` → `HESITANT`.
4. **ClamAV** (`brew install clamav`) — `clamdscan` if a daemon is running,
   else `clamscan`; can look inside dmg/pkg/zip/tar.
5. **YARA** (`brew install yara`) — bundled macOS starter rules in
   `rules/yara/brewcheck.yar`. Rules are tiered by their `severity` meta:
   `high` → `MALICIOUS`, `medium` → `SUSPICIOUS`, `hesitant` → `HESITANT`
   (aggressive/pedantic rules that warn without blocking).
6. **capa** (`pipx install flare-capa`) — *informational* capability surfacing,
   never a verdict.
7. **GitHub author credibility** — when the definition links a GitHub repo,
   rates the upstream author/repository 0–10 from public signals (stars,
   contributors, repo age, account age, license). Lenient by design (new authors
   are normal in OSS), so it never pushes the verdict past `HESITANT` — **with
   one exception**: a repository less than a month old yields `SUSPICIOUS`. Uses
   the public GitHub API; set `GITHUB_TOKEN` (or `GH_TOKEN`) for higher rate
   limits. The 0–10 score is always shown, even when good.
8. **VirusTotal upload** — opt-in (`--cloud`), size-capped, never silent.

Every external scanner is optional. If it isn't on `PATH`, that layer is
reported as `skipped (not installed)` with an install hint, and the report
states **which layers ran vs. skipped** — a verdict from 1/8 layers is weaker
than 8/8.

### Extraction safety

dmg/pkg are **extracted, never mounted or run** (`7z` for dmg, `pkgutil
--expand` for pkg). Zip extraction is in-process with a zip-slip guard and
size/count caps. All extraction is sandboxed inside the quarantine.

## Talking to brew (read-only)

brewcheck invokes `brew` for exactly one thing: `brew --cache [--cask] <name>`
to learn where brew *would* place a download. It never asks brew to download. If
brew isn't installed, brewcheck still scans and just skips the cache hand-off.

## Project layout

```
cmd/                 cobra commands, flag wiring, orchestration
internal/
  api/               Homebrew JSON API client (formula + cask)
  oci/               ghcr.io anonymous-token + blob fetch
  download/          streaming download + sha256, quarantine mgmt
  verify/            sha256 verification
  extract/           safe extraction (7z, pkgutil --expand), zip-slip guards
  scan/              vt, semgrep, clamav, yara, capa + pipeline orchestration
  brewcache/         `brew --cache` path oracle + atomic move
  report/            human + JSON report rendering
  deps/              external-tool detection + install hints
rules/               starter semgrep + yara rules
```

## Tests

```sh
go test ./...
```

Covers API parsing & platform bottle selection, sha256 match/mismatch/no_check,
the verify branch (proceed/abort/flag), report rendering & verdict aggregation,
the zip-slip guard, OCI URL parsing & blob streaming, and static-analysis
pattern detection. HTTP is mocked for the API/OCI clients.

## Known limitations / follow-ups (not in v0.1)

- **Only the current host platform's bottle is checked.** Cross-platform /
  multi-bottle checking in one run is a follow-up.
- No source-build (non-bottle) formula inspection — bottles only.
- In-process YARA via `hillu/go-yara` (currently shells out to `yara`).
- User-supplied rule paths (`--semgrep-rules`, `--yara-rules`) and a
  rule-update mechanism.
- capa is not yet wired to a representative binary in most cases.

> Reminder, kept visible everywhere: this tool detects known malware and
> suspicious patterns; it is not a defense against a novel, targeted
> supply-chain attack. The most valuable output is showing you what the install
> scripts actually do.
