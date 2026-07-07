/*
 * skillpacks yara-scan — starter rule pack.
 *
 * A small, high-signal set to get going. It is NOT a substitute for a real rule
 * corpus — point --rules at YARA-Rules, Neo23x0/signature-base, or your own set for
 * serious coverage. These are written to be low-false-positive and generic.
 */

rule Embedded_PE_Executable
{
    meta:
        description = "PE header present (dropped/embedded Windows executable)"
        author = "skillpacks"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }
    condition:
        $mz at 0 and $pe
}

rule UPX_Packed
{
    meta:
        description = "UPX packer section markers"
    strings:
        $u0 = "UPX0"
        $u1 = "UPX1"
        $u2 = "UPX!"
    condition:
        2 of them
}

rule PHP_Webshell_Eval
{
    meta:
        description = "PHP eval of decoded input and/or request-driven exec (webshell)"
    strings:
        $decode_eval = /eval\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13)/ nocase
        $req = /\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[/
        $eval = "eval(" nocase
        $sys = /\b(system|shell_exec|passthru|proc_open|popen)\s*\(/ nocase
    condition:
        $decode_eval or ($eval and $req) or ($sys and $req)
}

rule Windows_Exec_Download_Cradle
{
    meta:
        description = "Common Windows download/exec indicators"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "DownloadString" nocase
        $d = "Net.WebClient" nocase
        $e = "IEX(" nocase
        $f = "WScript.Shell" nocase
    condition:
        2 of them
}

rule Base64_Encoded_PE
{
    meta:
        description = "Base64-encoded MZ/PE header — encoded executable payload"
    strings:
        $a = "TVqQAAMAAAAEAAAA"
        $b = "TVpQAAIAAAAEAA8A"
        $c = "TVoAAAAAAAAAAAAA"
    condition:
        any of them
}

rule Shell_Pipe_To_Interpreter
{
    meta:
        description = "curl/wget piped straight into a shell (install-time dropper)"
    strings:
        $a = /(curl|wget)\s[^\n|]{0,200}\|\s*(sh|bash)\b/
    condition:
        $a
}
