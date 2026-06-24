# brewcheck

`brewcheck` fetches a Homebrew **formula** (bottle or source tarball) or **cask**
artifact *without using the `brew` binary to download it*, verifies its sha256
against Homebrew's
published hash, scans the verified bytes for malware and suspicious patterns,
weighs the credibility of the upstream GitHub author, and — **only on a clean
verdict** — hands the bytes to Homebrew's cache so a later `brew install` skips
the download.

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

## Install / build

```sh
go build -o brewcheck .
```

Requires Go (current stable). Third-party dependencies: `spf13/cobra` (CLI) and
`charmbracelet/bubbletea`+`bubbles`+`lipgloss` (the UI).

## Usage

```sh
brewcheck --formula <name>      # check a formula bottle (from ghcr.io)
brewcheck --cask <name>         # check a cask (direct vendor/GitHub URL)
brewcheck <name>                # auto-resolve type (errors if ambiguous)
brewcheck --tap user/repo <name>   # check a formula/cask from a third-party tap
```

### Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--formula <name>` / `--cask <name>` | — | explicit type (mutually exclusive) |
| `--tap <user/repo>` | — | resolve `<name>` from a third-party tap instead of the core API (requires brew) |
| `--build-from-source` / `-s` | `false` | scan the upstream source tarball instead of a bottle (auto-used for source-only formulae) |
| `--cache` / `--no-cache` | `true` | place verified bytes in brew's cache on a clean verdict |
| `--keep` | `false` | keep the quarantine dir (debugging) |
| `--cloud` | `false` | allow opt-in VirusTotal **file upload** when file hashes are unknown to VirusTotal |
| `--max-upload-size <bytes>` | `52428800` (50 MiB) | never cloud-upload above this, even with `--cloud` |
| `--json` | `false` | emit a machine-readable JSON report |
| `--verbose` / `-v` | `false` | log each pipeline step to stderr |
| `--quarantine-dir <path>` | OS temp | override the quarantine location |
| `--allow-new-repos` | `false` | don't flag GitHub repos younger than 30 days as `SUSPICIOUS` (credibility caps at `HESITANT` instead) |
| `--no-progress` | `false` | disable progress indicators (auto-disabled when stderr isn't a TTY or with `--verbose`) |

### Reusing brew's cache

Before downloading, brewcheck checks whether the artifact is **already in brew's
cache** and, if its sha256 matches Homebrew's published hash, scans that file in
place instead of re-downloading. Because the file is the user's own cached
download (not radioactive quarantine bytes), the cleanup policy is gentler:

| Verdict | Fresh download | Already in brew cache |
|---------|----------------|-----------------------|
| `CLEAN` / `HESITANT` | placed in cache | left in place |
| `SUSPICIOUS` | deleted | **kept** (warn only) |
| `MALICIOUS` | deleted | **removed from the cache** |

Reuse only happens when the hash is verifiable (never for a cask `no_check`) and
requires brew (for the cache path). Evicting a `MALICIOUS` file from the cache is
a safety action and happens regardless of `--no-cache`.

The sha256 check is load-bearing twice: it proves the scanned bytes are
byte-identical to what brew will install, and it closes the TOCTOU window —
brew re-verifies the cache file's hash at install time, so cached bytes are only
used because they still match.

### TUI vs. plain output

The UI runs **only** when stdout is a TTY. It falls back to plain text on stdout
when any of these hold:

- stdout is not a terminal (piped/redirected),
- `--no-progress` is passed,
- `--json` is passed (machine-readable output), or
- `--verbose` is passed (step logs go to stderr instead).

### Environment variables

| Variable | Used by | Effect |
|----------|---------|--------|
| `VT_API_KEY` | VirusTotal layers | enables hash lookup (and `--cloud` upload); the layer is skipped if unset |
| `GITHUB_TOKEN` / `GH_TOKEN` | GitHub author credibility | optional; raises the GitHub API rate limit from 60/hr to 5000/hr. The check still runs unauthenticated — it just skips with a hint when the limit is hit |
| `BREWCHECK_RULES_DIR` | Semgrep / YARA | overrides where the bundled `rules/` dir is found |

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
   one exception**: a repository less than a month old yields `SUSPICIOUS`
   (override with `--allow-new-repos`). Uses the public GitHub API; set
   `GITHUB_TOKEN` (or `GH_TOKEN`) for higher rate limits. The 0–10 score is
   always shown, even when good.
8. **VirusTotal upload** — opt-in (`--cloud`), size-capped, never silent.

Every external scanner is optional. If it isn't on `PATH`, that layer is
reported as `skipped (not installed)` with an install hint, and the report
states **which layers ran vs. skipped** — a verdict from 1/8 layers is weaker
than 8/8.

### Author credibility scoring

When the definition links a GitHub repo (parsed from `homepage`, falling back to
the source URL), brewcheck rates the upstream author/repository on a **0–10**
scale from cheap public-API signals. The weighting follows priority order,
normalized to 10:

| Signal | Max points | Buckets (log-ish) |
|--------|-----------:|-------------------|
| Stars | 4.0 | 1 / 10 / 50 / 200 / 1k / 5k |
| Contributors | 2.0 | 1 / 2 / 5 / 10 / 50 |
| Repo age | 2.0 | 1mo / 6mo / 1y / 3y |
| Account/org age | 1.5 | 6mo / 1y / 3y |
| License present | 0.5 | — |

The score is **always displayed**, even when healthy, as a gauge:

```
credibility: [██████████] 10/10  (github.com/jqlang/jq)
    35,018★ · 248 contributors · repo age 13.9y · org age 4.1y · no license
```

This check is **deliberately lenient** — new authors are normal in open source,
so a low score never pushes the verdict past `HESITANT` (a not-brand-new repo
scoring ≤ 3/10 raises a non-blocking warning). Unknown signals are not punished.
**The one exception:** a repository **less than a month old (30 days)** raises a
`SUSPICIOUS` finding regardless of its other signals — which blocks caching and
deletes the bytes. Pass **`--allow-new-repos`** to disable this hard rule: a
sub-month repo then caps at a non-blocking `HESITANT` warning (it's still shown,
just not treated as suspicious) — useful when you knowingly install young or
freshly-published projects. Network errors, rate limits, and missing repos never
affect the verdict.

### Extraction safety

dmg/pkg are **extracted, never mounted or run** (`7z` for dmg, `pkgutil
--expand` for pkg). Zip extraction is in-process with a zip-slip guard and
size/count caps. All extraction is sandboxed inside the quarantine.

## Talking to brew (read-only)

brewcheck invokes `brew` for the cache oracle — `brew --cache [--cask] <name>`,
to learn where brew *would* place a download — and, with `--tap`, for read-only
metadata (`brew info --json=v2`). It never asks brew to download an artifact. If
brew isn't installed, the core path still scans and just skips the cache
hand-off; `--tap`, however, requires brew (see below).

## Third-party taps

The formulae.brew.sh JSON API only serves the official `homebrew/core` and
`homebrew/cask` taps. To scan something from a third-party tap, pass `--tap`:

```sh
brewcheck --tap nikitabobko/tap --cask aerospace
brewcheck --tap felixkratz/formulae sketchybar      # positional name works too
```

For taps, brewcheck resolves metadata with `brew info --json=v2 <tap>/<name>`
(brew auto-taps the repo if needed — that fetches only the *formula
definitions*, never the artifact). Everything after resolution is identical to
the core path: download into quarantine → verify sha256 → scan → cache. Notes:

- **Requires brew** (the API can't serve taps); a clear error is shown if it's
  absent.
- The artifact is fetched directly from wherever the definition points — ghcr.io
  (OCI) for bottles published there, or a plain `GET` for bottles/casks hosted on
  GitHub releases or a custom `root_url`.
- Source-only tap formulae (no bottle) fall back to a source build automatically
  (see below), so they're scanned rather than rejected.

## Source builds

For a formula without a bottle for your platform — or when you pass
`--build-from-source` / `-s` — brewcheck scans the **upstream source tarball**
(`urls.stable.url`) instead of a bottle, exactly the artifact `brew install`
would compile. It's the same pipeline: download → verify against the formula's
published `urls.stable.checksum` → extract & scan the source → cache.

- The bottle is still preferred when one exists; source is the fallback (or
  forced with `-s`), matching `brew install` / `brew install --build-from-source`.
- The source tarball is cached at brew's *source* path (`brew --cache
  --build-from-source <name>`), distinct from the bottle path — so cache reuse
  and the clean-verdict hand-off both target the right file.
- Git/HEAD sources (a repo URL with no published checksum) aren't supported:
  with nothing to verify against, the hash layer flags the run and never caches.
- The report labels these runs `(formula, source build)`.

## Project layout

```
cmd/                 cobra commands, flag wiring, orchestration
internal/
  api/               Homebrew JSON API client (formula + cask)
  oci/               ghcr.io anonymous-token + blob fetch
  download/          streaming download + sha256, quarantine mgmt
  verify/            sha256 verification
  extract/           safe extraction (7z, pkgutil --expand), zip-slip guards
  scan/              static, vt, semgrep, clamav, yara, capa, github + pipeline orchestration
  brewcache/         `brew --cache` path oracle + atomic move
  report/            verdict/finding types + plain human & JSON rendering
  ui/                bubbletea UI (progress + styled result)
  progress/          byte-counting reader + TTY detection
  deps/              external-tool detection + install hints
rules/               starter semgrep + yara rules
```

## Tests

```sh
go test ./...
```

Covers API parsing & platform bottle selection, GitHub repo-URL derivation,
sha256 match/mismatch/no_check, the verify branch (proceed/abort/flag), report
rendering & verdict aggregation (including `HESITANT`), the zip-slip guard, OCI
URL parsing & blob streaming, static-analysis pattern detection, and the author
credibility scoring (weights, the sub-month `SUSPICIOUS` exception, and the
contributor-count `Link`-header parse). HTTP is mocked for the API/OCI/GitHub
clients.


> Reminder, kept visible everywhere: this tool detects known malware and
> suspicious patterns; it is not a defense against a novel, targeted
> supply-chain attack. The most valuable output is showing you what the install
> scripts actually do.
