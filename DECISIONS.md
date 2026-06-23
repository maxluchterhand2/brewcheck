# DECISIONS

Open implementation choices made while building brewcheck v0.1, with rationale.
The spec is explicit in many places; this file documents only the places it
left open.

## OCI / ghcr.io token handling
- Homebrew bottle URLs from the JSON API already point at the **blob** endpoint
  (`.../blobs/sha256:<digest>`), so brewcheck does **not** fetch a manifest. It
  resolves the repository from the URL (`/v2/<repo>/blobs/`) and streams the
  blob directly. This is the minimal token → blob flow; no heavyweight registry
  library is pulled in (`internal/oci` is ~150 lines).
- We acquire an **anonymous pull token** from
  `https://ghcr.io/token?service=ghcr.io&scope=repository:<repo>:pull`. If that
  endpoint is unreachable we fall back to Homebrew's well-known anonymous bearer
  `QQ==`, which also authorizes public blobs. Both were verified to return the
  same bytes. Resolving a token is preferred because it does not depend on an
  undocumented constant continuing to work.

## Platform / bottle selection
- v0.1 checks **only the current host platform's bottle** (documented in README
  as a known limitation; multi-bottle is a follow-up).
- The host key is derived from `runtime.GOARCH` plus the macOS codename, which
  is mapped from `sw_vers -productVersion` (a read-only query — never `brew`).
  The map (`api.macCodenames`) currently covers big_sur(11) … tahoe(26). An
  unmapped major version is a hard error with a clear "update the map" message,
  rather than silently guessing a bottle for the wrong OS.
- `SelectBottle` falls back to an `all` (noarch) bottle when no per-platform key
  matches, and otherwise errors listing the available keys.

## sha256 verification & the `no_check` case
- Verification happens **before any scanning, extraction, or caching**. A
  mismatch aborts immediately: bytes are deleted, verdict is `SUSPICIOUS`, and
  the finding is labelled `HASH_MISMATCH` and surfaced prominently.
- Some casks publish `sha256: "no_check"` (auto-updating apps). brewcheck treats
  this as **unverifiable**: it still scans (scanning is useful), marks
  `hash_verified=false`, adds a `SUSPICIOUS` finding, and **never caches** —
  because the whole TOCTOU guarantee depends on a verified hash, and brew itself
  won't re-verify a `no_check` artifact at install time.

## Cache hand-off
- `brew` is used **only** as a path oracle (`brew --cache [--cask] <name>`),
  never to download. We never reverse-engineer the cache filename convention.
- Caching requires `verdict == CLEAN` **and** a verified hash **and** brew on
  PATH. If brew is absent, scanning still runs; the cache step is skipped and
  reported.
- Placement is atomic: `os.Rename` first, falling back to copy+`fsync`+rename
  within the cache directory on a cross-filesystem error, so brew never sees a
  partial file.

## Extraction (never mount, never execute)
- `.pkg`/`.mpkg`: `pkgutil --expand` (never runs the installer); extracted
  `preinstall`/`postinstall`/`Scripts/*` are surfaced to static analysis.
- `.dmg`: extracted with `7z` so nothing is **mounted** (`hdiutil attach` is
  never used).
- `.zip`: extracted **in-process** with a zip-slip guard (`safeJoin`) plus file
  count and uncompressed-size caps. This is the path with the dedicated tests.
- Bottles (`.tar.gz`) and other archives: extracted via `7z` when present;
  otherwise extraction is skipped and scanners run over the file directly
  (ClamAV/libclamav can look inside archives without unpacking).
- All extraction is sandboxed to a `scratch/` subdir inside the quarantine.

## Scanner orchestration
- Layer 1 (VirusTotal hash lookup) runs first and can **short-circuit** to
  `MALICIOUS` on a definitive hit (≥3 engines), skipping the local layers. When
  it does, the skipped layers are recorded with that reason so the report stays
  honest.
- Layers 2 & 3 (static, semgrep, clamav, yara, capa) run **in parallel** and are
  aggregated. Every scanner is optional: missing tools are recorded as
  `skipped` with an install hint and never cause a hard failure.
- Verdict severity is deliberately conservative: pattern-based static findings
  are `suspicious` (worth a human look), and only the authoritative scanners
  (VT detections, ClamAV/YARA hits) produce `malicious` — **except** YARA rules
  tagged `severity = "hesitant"` (see below).

## HESITANT verdict
- A fifth verdict, `HESITANT`, sits **between** `CLEAN` and `SUSPICIOUS`
  (precedence: `MALICIOUS > SUSPICIOUS > HESITANT > CLEAN`). It exists for
  intentionally aggressive, false-positive-prone heuristics where staying silent
  would be dishonest but blocking the install would be wrong.
- Unlike `SUSPICIOUS`/`MALICIOUS`, a `HESITANT` artifact is **not deleted** and
  **is handed to the cache** (still gated on a verified hash), exactly like
  `CLEAN`. The only difference is the report prints a `⚑` warning telling the
  user which item to eyeball before `brew install`.
- Exit code is **`4`** — deliberately not slotted into the spec's `0–3` range so
  existing tooling that checks `0/1/2/3` is unaffected, while CI that wants to
  notice the soft warning still can. Documented as an extension to spec §7.
- `HESITANT` is driven by YARA rules with `severity = "hesitant"` and by Semgrep
  rules with `severity: INFO`. The `report.SeverityHesitant` finding severity is
  the general mechanism, so any future layer can raise a hesitant finding the
  same way.

## Semgrep rules
- Severity maps onto verdicts: `ERROR`/`WARNING` → `suspicious`, `INFO` →
  `hesitant`. Pattern-based static findings are intentionally capped at
  `suspicious` (only authoritative scanners — VT, ClamAV, YARA `high` — produce
  `malicious`), and the pedantic / FP-prone checks live at `INFO`.
- Shell rules use `languages: [generic]`, **not** `[bash, generic]`. Semgrep
  rejects `generic` combined with a named language in one rule ("invalid
  language generic"), and `generic` alone applies the `pattern-regex` rules to
  every extracted script path regardless of shebang/extension — which is what we
  want for pkg `pre/postinstall` scripts that often have neither. (The v0.1
  starter rules shipped with the invalid `[bash, generic]` combo, which would
  have errored the whole config; fixed here.)
- Ruby rules are deliberately targeted (suspicious *commands* inside a shell-out)
  rather than flagging every `system`/backtick, because legitimate formulae
  shell out constantly during builds and a broad rule would bury the signal.

## VirusTotal
- Hash lookup uploads **nothing**. The free-tier rate limit (HTTP 429) is
  surfaced as a layer error rather than retried aggressively.
- File upload is strictly opt-in (`--cloud`), never silent, and never over
  `--max-upload-size` (default 50 MiB). The report states the privacy
  implication before/while uploading.
- `maliciousThreshold = 3` engines is the cut for "definitive known-bad", to
  avoid single false-positive engines flipping the verdict.

## GitHub author credibility
- Runs whenever a GitHub `owner/repo` can be parsed from the definition's
  `homepage` or source URL (homepage preferred; falls back to the source URL).
  Works for both formulae and casks, though formulae are the primary case.
- Three cheap public API calls per check: `GET /repos/{owner}/{repo}` (stars,
  created_at, license, owner), the contributor count via the `Link` header of a
  `per_page=1` contributors listing (the standard trick — avoids paging through
  everyone), and `GET /users/{owner}` for account age. All four of the
  user-requested signals (stars, contributors, repo age, account age) are
  available via the API, so none were scrapped; license + archived/fork flags
  are folded in as cheap extras.
- Scoring is a pure function (`Score(metrics, now)`) so it is fully
  table-testable. Weighting follows the requested priority order, normalized to
  a 0–10 total: stars (max 4.0), contributors (max 2.0), repo age (max 2.0),
  account age (max 1.5), license (max 0.5). Buckets are log-ish (e.g. stars:
  1/10/50/200/1k/5k) so a handful of stars still earns a little credit —
  deliberately **not harsh**, since new authors are normal in open source.
- Unknown signals are not punished: unknown contributor count earns a small
  neutral credit and unknown ages simply contribute nothing.
- **Verdict ceiling**: this layer can raise at most a `HESITANT` finding (when a
  not-brand-new repo scores ≤ 3/10) — never `SUSPICIOUS`/`MALICIOUS` — *except*
  the one explicit exception: a repository younger than **one month** (30 days)
  raises a `SUSPICIOUS` finding regardless of its other signals, which (given the
  aggregation rules) blocks caching and deletes the bytes.
- The 0–10 score is always surfaced via `report.Credibility` (rendered as a
  `[████░░░░░░] N/10` gauge and included in `--json`), even for healthy repos
  that produce no finding, because the score itself is the requested output.
- Network/rate-limit/not-found problems never affect the verdict: a rate limit
  is `skipped` (with a hint to set `GITHUB_TOKEN`), other errors are `error`,
  and a linked-but-missing repo is `ran` with a note and no score.

## capa
- A single representative binary is hard to identify generically from a bottle
  or cask in v0.1, so capa is usually reported as skipped ("no single binary
  identified"). When wired to a binary, capa output is **informational only**
  (never a verdict), and analysis failures (common for Mach-O) are non-fatal.

## YARA rules layout
- YARA is invoked over a **single** bundled rules file
  (`rules/yara/brewcheck.yar`) because the `yara` CLI takes a rules file, not a
  directory. Semgrep's `--config` accepts the `rules/semgrep/` directory
  directly. User-supplied rule paths are a documented follow-up.
- YARA is run with `-m` so each rule's metadata is printed on the match line.
  The scanner reads each rule's `severity` meta and maps it to a finding
  severity: `high`/`critical` → `malicious`, `medium` → `suspicious`,
  `low`/`hesitant`/`aggressive` → `hesitant`, and a **missing/unknown** severity
  → `malicious` (a hit with no declared tier is treated as definitive, matching
  the original v0.1 contract). This is what lets a single ruleset express all
  three of "delete it", "don't cache it", and "cache it but warn".
- Rules are tiered on purpose: `high` is reserved for patterns essentially never
  legitimate in a Homebrew artifact (interactive reverse shells, `NOPASSWD`
  sudoers edits); `hesitant` holds the pedantic, FP-prone heuristics (quarantine
  stripping, keychain/TCC references, long base64 blobs) that we want surfaced
  without nuking a legitimate cask.

## Rules discovery
- The bundled `rules/` dir is located via `BREWCHECK_RULES_DIR`, then next to
  the executable, then `./rules`. If not found, the rule-based scanners simply
  find no rules and report accordingly.

## CLI ergonomics
- `--no-cache` is wired as an explicit flag (pflag does not auto-generate the
  negated form of `--cache`); it overrides `--cache`.
- `--keep` keeps the quarantine for debugging across all verdicts. Without it,
  bytes are deleted on any non-clean verdict and after a successful cache
  hand-off.
