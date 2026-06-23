/*
 * brewcheck starter YARA rules — macOS-focused heuristics.
 *
 * Severity tiers (read by internal/scan/yara via `yara -m`):
 *
 *   severity = "high"      -> MALICIOUS  (definitive; bytes deleted, never cached)
 *   severity = "medium"    -> SUSPICIOUS (not cached by default; review)
 *   severity = "hesitant"  -> HESITANT   (bytes ARE cached, but the user is warned;
 *                                         intentionally aggressive / FP-prone rules)
 *   (no severity meta)      -> MALICIOUS  (a hit with no declared tier is definitive)
 *
 * Philosophy for the "hesitant" tier: be harsh and pedantic. We would rather
 * flag a legitimate installer's `xattr -d com.apple.quarantine` and make the
 * user glance at it than stay silent. HESITANT does not block the install — it
 * just refuses to pretend we saw nothing.
 *
 * Reserve "high" for patterns that are essentially never legitimate inside a
 * Homebrew artifact (interactive reverse shells, NOPASSWD sudoers edits).
 */

/* ------------------------------------------------------------------ *
 * HIGH — essentially never legitimate. Definitive MALICIOUS.
 * ------------------------------------------------------------------ */

rule Macho_Reverse_Shell_Strings
{
    meta:
        description = "Mach-O binary containing reverse-shell / remote-exec indicators"
        severity    = "high"
    strings:
        $devtcp   = "/dev/tcp/" ascii
        $bashi    = "bash -i" ascii
        $nc_e     = "nc -e" ascii
        $py_pty   = "pty.spawn" ascii
        $magic1   = { CF FA ED FE }   // Mach-O 64-bit little-endian
        $magic2   = { CA FE BA BE }   // universal (fat) binary
    condition:
        (any of ($magic*)) and (any of ($devtcp, $bashi, $nc_e, $py_pty))
}

rule Shell_Reverse_Shell_OneLiner
{
    meta:
        description = "Classic /dev/tcp interactive reverse shell one-liner"
        severity    = "high"
    strings:
        // bash -i >& /dev/tcp/host/port 0>&1  (and spacing variants)
        $a = /(ba|z)?sh\s+-i[^\n]{0,80}\/dev\/tcp\/[^\n]{0,80}0>&1/ nocase
        $b = /\/dev\/tcp\/[0-9a-z.\-]{1,80}\/[0-9]{1,5}[^\n]{0,40}0>&1/ nocase
    condition:
        any of them
}

rule Netcat_Backconnect
{
    meta:
        description = "Netcat/ncat backconnect or mkfifo reverse shell"
        severity    = "high"
    strings:
        $a = /n(c|cat)\s+(-[a-z]*\s+)*-e\s+\/(bin|usr)\b/ nocase
        $b = /mkfifo[^\n]{0,60}\|[^\n]{0,40}n(c|cat)\s/ nocase
        $c = /rm\s+[^\n]{0,20}\/tmp\/[a-z0-9_.]+;\s*mkfifo/ nocase
    condition:
        any of them
}

rule Sudoers_NOPASSWD_Injection
{
    meta:
        description = "Writes a passwordless-sudo entry into /etc/sudoers(.d)"
        severity    = "high"
    strings:
        $path1 = "/etc/sudoers" ascii
        $path2 = "/private/etc/sudoers" ascii
        $np    = "NOPASSWD" ascii
        $all   = "ALL=(ALL" ascii nocase
    condition:
        (any of ($path*)) and ($np or $all)
}

/* ------------------------------------------------------------------ *
 * MEDIUM — concerning, sometimes legitimate. SUSPICIOUS.
 * ------------------------------------------------------------------ */

rule Curl_Pipe_Shell_In_Script
{
    meta:
        description = "Downloads and pipes directly into a shell (curl|sh, wget|sh, base64|sh)"
        severity    = "medium"
    strings:
        $a = /curl[^\n|]{0,200}\|\s*(ba|z)?sh/ nocase
        $b = /wget[^\n|]{0,200}\|\s*(ba|z)?sh/ nocase
        $c = /base64\s+(-d|--decode)[^\n|]{0,200}\|\s*(ba|z)?sh/ nocase
    condition:
        any of them
}

rule Eval_Decoded_Payload
{
    meta:
        description = "eval/exec of base64- or hex-decoded content (obfuscated execution)"
        severity    = "medium"
    strings:
        $a = /eval\s+[^\n]{0,40}base64\s+(-d|--decode)/ nocase
        $b = /eval\s*\(\s*[^\n]{0,40}(atob|fromCharCode|decode)/ nocase
        $c = /python[0-9]?\s+-c\s+[^\n]{0,60}(exec|eval)\s*\(/ nocase
        $d = /perl\s+-e\s+[^\n]{0,60}eval/ nocase
    condition:
        any of them
}

rule Suspicious_Persistence_LaunchAgent
{
    meta:
        description = "Embedded LaunchAgent/LaunchDaemon plist with RunAtLoad"
        severity    = "medium"
    strings:
        $plist     = "<plist" ascii nocase
        $label     = "<key>Label</key>" ascii
        $runatload = "<key>RunAtLoad</key>" ascii
        $program   = "<key>ProgramArguments</key>" ascii
    condition:
        $plist and $label and $runatload and $program
}

rule Write_To_LaunchDaemons_Path
{
    meta:
        description = "Script writes a plist into a system/user Launch{Agents,Daemons} dir"
        severity    = "medium"
    strings:
        $a = /\/Library\/LaunchDaemons\/[^\n"']{1,80}\.plist/ nocase
        $b = /\/Library\/LaunchAgents\/[^\n"']{1,80}\.plist/ nocase
        $load = /launchctl\s+(load|bootstrap|enable)/ nocase
    condition:
        (any of ($a, $b)) and $load
}

rule Download_To_Raw_IP
{
    meta:
        description = "Fetches an artifact from a raw IPv4 address rather than a hostname"
        severity    = "medium"
    strings:
        $a = /(curl|wget)[^\n]{0,80}https?:\/\/([0-9]{1,3}\.){3}[0-9]{1,3}/ nocase
    condition:
        $a
}

rule Disable_Gatekeeper
{
    meta:
        description = "Disables Gatekeeper / code-signing enforcement (spctl, csrutil)"
        severity    = "medium"
    strings:
        $a = "spctl --master-disable" ascii nocase
        $b = /spctl\s+--add\s/ nocase
        $c = "csrutil disable" ascii nocase
        $d = /defaults\s+write[^\n]{0,40}LSQuarantine\s+-bool\s+(false|NO)/ nocase
    condition:
        any of them
}

/* ------------------------------------------------------------------ *
 * HESITANT — aggressive, pedantic, false-positive-prone. Cache + WARN.
 * ------------------------------------------------------------------ */

rule Strip_Quarantine_Xattr
{
    meta:
        description = "Removes the com.apple.quarantine attribute (common in legit casks, but worth a glance)"
        severity    = "hesitant"
    strings:
        $a = /xattr\s+(-[a-z]*\s+)*-d\s+com\.apple\.quarantine/ nocase
        $b = /xattr\s+-cr?\b/ nocase
        $c = "com.apple.quarantine" ascii
    condition:
        $a or $b or ($c and filesize < 2MB)
}

rule Osascript_Admin_Privileges
{
    meta:
        description = "AppleScript requesting administrator privileges (privilege escalation prompt)"
        severity    = "hesitant"
    strings:
        $osa  = "osascript" ascii nocase
        $priv = "with administrator privileges" ascii nocase
        $do   = "do shell script" ascii nocase
    condition:
        $priv or ($osa and $do)
}

rule AppleScript_Password_Phishing
{
    meta:
        description = "AppleScript dialog asking for a password with hidden input (credential phishing pattern)"
        severity    = "hesitant"
    strings:
        $dlg  = "display dialog" ascii nocase
        $hid  = "hidden answer" ascii nocase
        $pw   = "password" ascii nocase
    condition:
        $dlg and $hid and $pw
}

rule Keychain_Access_Reference
{
    meta:
        description = "References the macOS keychain or dumps credentials (security(1) / login.keychain)"
        severity    = "hesitant"
    strings:
        $a = "login.keychain-db" ascii nocase
        $b = "login.keychain" ascii nocase
        $c = /security\s+(dump-keychain|find-(generic|internet)-password)/ nocase
        $d = "/Library/Keychains/" ascii nocase
    condition:
        any of them
}

rule TCC_Privacy_Database_Reference
{
    meta:
        description = "Touches the TCC privacy database (often used to fake or bypass consent)"
        severity    = "hesitant"
    strings:
        $a = "TCC.db" ascii nocase
        $b = "com.apple.TCC" ascii
        $c = "/Library/Application Support/com.apple.TCC" ascii nocase
    condition:
        any of them
}

rule Browser_Credential_Theft_Paths
{
    meta:
        description = "References browser cookie/login-data stores (info-stealer pattern)"
        severity    = "hesitant"
    strings:
        $chrome   = "Google/Chrome/Default/Login Data" ascii nocase
        $cookies  = "Google/Chrome/Default/Cookies" ascii nocase
        $firefox  = "Firefox/Profiles" ascii nocase
        $logins   = "logins.json" ascii nocase
        $cryptokey = "Local State" ascii
    condition:
        2 of them
}

rule Crypto_Wallet_Reference
{
    meta:
        description = "References crypto-wallet data directories (clipper / stealer pattern)"
        severity    = "hesitant"
    strings:
        $a = "Exodus" ascii
        $b = "Electrum" ascii
        $c = "Coinomi" ascii
        $d = "MetaMask" ascii
        $e = ".bitcoin" ascii
        $f = "wallet.dat" ascii nocase
    condition:
        2 of them
}

rule Long_Base64_Blob
{
    meta:
        description = "Very long contiguous base64 run (possible obfuscated/embedded payload)"
        severity    = "hesitant"
    strings:
        $b64 = /[A-Za-z0-9+\/]{260,}={0,2}/
    condition:
        $b64
}

rule Hex_Encoded_Shell_Bytes
{
    meta:
        description = "Long \\x-escaped byte run (possible shellcode / obfuscated string)"
        severity    = "hesitant"
    strings:
        $hex = /(\\x[0-9a-fA-F]{2}){24,}/
    condition:
        $hex
}

rule Curl_Download_Chmod_Exec
{
    meta:
        description = "Downloads a file, chmods it executable, and runs it (stager pattern)"
        severity    = "hesitant"
    strings:
        $dl   = /(curl|wget)\s+[^\n]{0,120}(\/tmp\/|\/var\/tmp\/|\$TMPDIR)/ nocase
        $chmod = /chmod\s+\+?x/ nocase
    condition:
        $dl and $chmod
}

rule Hidden_Executable_In_Tmp
{
    meta:
        description = "Creates/executes a hidden file under a temp directory"
        severity    = "hesitant"
    strings:
        $a = /\/(tmp|var\/tmp)\/\.[a-z0-9_]{1,40}/ nocase
        $b = /\$TMPDIR\/\.[a-z0-9_]{1,40}/ nocase
    condition:
        any of them
}

rule Environment_Exfiltration
{
    meta:
        description = "Harvests environment / system info and pipes it to the network"
        severity    = "hesitant"
    strings:
        $env  = /(printenv|\benv\b|set\b)[^\n|]{0,60}\|[^\n]{0,40}(curl|nc|wget)/ nocase
        $whoami = /(whoami|hostname|system_profiler)[^\n|]{0,60}\|[^\n]{0,40}(curl|nc|wget)/ nocase
    condition:
        any of them
}

rule Self_Delete_Tracks
{
    meta:
        description = "Deletes itself / clears shell history (anti-forensics)"
        severity    = "hesitant"
    strings:
        $a = /rm\s+-[rf]+\s+"?\$0/ nocase
        $b = "history -c" ascii nocase
        $c = "unset HISTFILE" ascii nocase
        $d = "/dev/null 2>&1 &" ascii
    condition:
        any of ($a, $b, $c) or ($d and ($a or $b or $c))
}

rule Obfuscated_String_Reversal
{
    meta:
        description = "Reverses a string before executing it (rev | sh, [::-1] obfuscation)"
        severity    = "hesitant"
    strings:
        $a = /\brev\b[^\n|]{0,40}\|\s*(ba|z)?sh/ nocase
        $b = "[::-1]" ascii
        $c = /echo\s+[^\n|]{0,80}\|\s*rev/ nocase
    condition:
        any of them
}
