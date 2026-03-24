/*
 * VulnScan Custom YARA Rules
 * ─────────────────────────────────────────────────────────
 * Add your own YARA rules here to extend VulnScan's
 * pattern-matching capabilities.
 *
 * Documentation: https://yara.readthedocs.io/
 * ─────────────────────────────────────────────────────────
 */

rule Default_Credentials_Config {
    meta:
        description = "Detects default or example credentials left in config files"
        severity = "High"
        remediation = "Remove default credentials from config files; use environment variables."
    strings:
        $a = "admin:admin" nocase
        $b = "root:root" nocase
        $c = "admin:password" nocase
        $d = "admin:1234" nocase
        $e = "username: admin" nocase
        $f = "changeme" nocase
    condition:
        any of them
}

rule Open_Redirect_Pattern {
    meta:
        description = "Detects potential open redirect vulnerability patterns"
        severity = "Medium"
        remediation = "Validate redirect URLs against an allowlist; never redirect to user-supplied URLs directly."
    strings:
        $r1 = "redirect_to=" nocase
        $r2 = "next=" nocase
        $r3 = "returnUrl=" nocase
        $r4 = "return_url=" nocase
        $unsafe = "http" nocase
    condition:
        ($r1 or $r2 or $r3 or $r4) and $unsafe
}

rule Cleartext_Protocol_Usage {
    meta:
        description = "Detects connection to cleartext protocols in code"
        severity = "Medium"
        remediation = "Replace FTP, HTTP, Telnet with SFTP, HTTPS, SSH respectively."
    strings:
        $ftp  = "ftp://" nocase
        $http = "http://" nocase
        $tel  = "telnet://" nocase
    condition:
        2 of them
}

rule JWT_None_Algorithm {
    meta:
        description = "Detects potential JWT 'none' algorithm vulnerability"
        severity = "Critical"
        remediation = "Explicitly reject 'none' algorithm in JWT libraries; always verify signatures."
    strings:
        $a = "\"alg\": \"none\"" nocase
        $b = "alg=none" nocase
        $c = "algorithm='none'" nocase
        $d = "algorithms=[\"none\"]" nocase
    condition:
        any of them
}

rule Debug_Mode_Enabled {
    meta:
        description = "Detects debug mode enabled in production-like configuration"
        severity = "High"
        remediation = "Set DEBUG=False in production; use environment-specific configuration."
    strings:
        $a = "DEBUG = True" nocase
        $b = "debug=true" nocase
        $c = "app.run(debug=True)" nocase
        $d = "NODE_ENV=development" nocase
    condition:
        any of them
}
