package yara

// EmbeddedCoreLinuxRules defines high-confidence, curated Linux threat signatures
// shipped directly inside Aether for zero-download, out-of-the-box detection.
const EmbeddedCoreLinuxRules = `
rule Linux_Webshell_PHP_Generic_Backdoor {
    meta:
        description = "Detects obfuscated PHP code execution backdoors and one-liners"
        severity = "alert"
        score = 90
        author = "Aether Security Team"
        mitre = "T1505.003"
        confidence = "high"
    strings:
        $eval_post   = /(eval|assert|passthru|shell_exec|system|popen|proc_open|pcntl_exec)\s*\(\s*((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|pack)\s*\(\s*)*(\$_(POST|GET|REQUEST|COOKIE|SERVER)|\$GLOBALS\[['"]_(POST|GET|REQUEST|COOKIE)['"]\])\[/ nocase
        $call_user   = /call_user_func(_array)?\s*\(\s*['"]?(eval|assert|passthru|shell_exec|system|popen|proc_open)['"]?\s*,\s*.*\$_(POST|GET|REQUEST|COOKIE|SERVER)/ nocase
        $create_func = /create_function\s*\(\s*['"]\s*['"]\s*,\s*\$_(POST|GET|REQUEST)\[/ nocase
        $preg_eval   = /preg_replace\s*\(\s*['"]\/.+\/e['"]\s*,\s*\$_(POST|GET|REQUEST)\[/ nocase
        $var_assign  = /\$[a-zA-Z0-9_]+\s*=\s*((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|stripslashes)\s*\(\s*)*\$_(POST|GET|REQUEST|COOKIE|SERVER)\[/ nocase
        $var_exec    = /(eval|assert|passthru|shell_exec|system|popen|proc_open)\s*\(\s*\$[a-zA-Z0-9_]+\s*\)/ nocase
        $dyn_call    = /\$[a-zA-Z0-9_]+\s*\(\s*\$_(POST|GET|REQUEST|COOKIE)\[/ nocase
    condition:
        filesize < 2MB and ($eval_post or $call_user or $create_func or $preg_eval or $dyn_call or ($var_assign and $var_exec))
}

rule Linux_Webshell_PHP_Known_Families {
    meta:
        description = "Detects popular Linux PHP webshell frameworks (c99, r57, WSO, b374k, Weevely, China Chopper)"
        severity = "alert"
        score = 95
        author = "Aether Security Team"
        mitre = "T1505.003"
        confidence = "high"
    strings:
        $c99   = "c99shell" nocase
        $r57   = "r57shell" nocase
        $wso   = "WSO_VERSION" ascii
        $b374k = "b374k" ascii
        $weevely = "weevely" nocase
        $filesman = "FilesMan" ascii
        $phpspy = "phpspy" nocase
        $chopper = "@eval($_POST[" ascii
        $alfa   = "Alfa Team - Alfa Shell" ascii
    condition:
        filesize < 5MB and (any of them)
}

rule Linux_Webshell_JSP_Runtime_Exec {
    meta:
        description = "Detects JSP webshell executing arbitrary system commands"
        severity = "alert"
        score = 90
        author = "Aether Security Team"
        mitre = "T1505.003"
        confidence = "high"
    strings:
        $jsp_tag   = "<%" ascii
        $runtime   = "Runtime.getRuntime().exec(" ascii
        $procbuild = "ProcessBuilder" ascii
        $req_param = "request.getParameter(" ascii
    condition:
        filesize < 1MB and $jsp_tag and ($runtime or $procbuild) and $req_param
}

rule Linux_Backdoor_Reverse_Shell_OneLiner {
    meta:
        description = "Detects interactive reverse shell one-liners across bash, python, perl, ruby, and netcat"
        severity = "alert"
        score = 95
        author = "Aether Security Team"
        mitre = "T1059.004"
        confidence = "high"
    strings:
        $bash_devtcp   = /((\/usr)?\/bin\/)?(ba|da|z|k)?sh\s+.*>&?\s*\/dev\/(tcp|udp)\/[^\s;]+/ nocase
        $devtcp_redir  = /\/dev\/(tcp|udp)\/[^\s;]+\s+(0>&1|>&0|>&2)/ nocase
        $bash_exec_tcp = /(exec\s+)?[0-9]*<>\/dev\/(tcp|udp)\/[^\s;]+/ nocase
        $nc_e          = /(nc|ncat|netcat)(\.[a-z]+)?\s+.*(-[a-z]*[ec][a-z]*|--(sh-)?exec)\s+['"]?((\/usr)?\/bin\/)?(ba|da|z|k)?sh/ nocase
        $nc_pipe       = /(mkfifo|mknod)\s+\S+.*\|\s*(nc|ncat|netcat)(\.[a-z]+)?/ nocase
        $py_socket     = /python[23]?\s+.*['"]import\s+(ssl,\s*)?socket.*socket\.socket/ nocase
        $perl_socket   = /perl\s+.*['"]use\s+Socket/ nocase
        $ruby_socket   = /ruby\s+.*['"](require\s+['"]socket['"]|TCPSocket\.open)/ nocase
        $lua_socket    = /lua\s+.*['"]require\s*\(?['"]socket['"]\)?.*socket\.tcp/ nocase
        $node_socket   = /node(js)?\s+.*['"]require\s*\(?['"](net|child_process)['"]\)?/ nocase
        $awk_tcp       = /awk\s+.*inet\/tcp/ nocase
        $socat_exec    = /socat\s+(exec|pty|tcp|system).*(exec|pty|tcp|system)/ nocase
    condition:
        filesize < 2MB and (any of them)
}

rule Linux_Backdoor_Encrypted_Reverse_Shell {
    meta:
        description = "Detects encrypted reverse shells using OpenSSL s_client, Socat SSL, or Python SSL sockets"
        severity = "alert"
        score = 95
        author = "Aether Security Team"
        mitre = "T1573.002"
        confidence = "high"
    strings:
        $openssl_pipe = /openssl\s+s_client\s+(-quiet\s+)?-connect\s+[^\s|;&]+.*\|\s*((\/usr)?\/bin\/)?(ba)?sh/ nocase
        $openssl_in   = /openssl\s+s_client\s+(-quiet\s+)?-connect\s+<\s*\/tmp\// nocase
        $socat_ssl    = /socat\s+openssl-connect:[^\s,]+.*exec:((\/usr)?\/bin\/)?(ba)?sh/ nocase
    condition:
        filesize < 2MB and (any of them)
}

rule Linux_Implant_RedTeam_Persistence_Framework {
    meta:
        description = "Detects Linux red-team persistence frameworks, stealth procfs mounting, and backdoor installers"
        severity = "alert"
        score = 95
        author = "Aether Security Team"
        mitre = "T1547.001"
        confidence = "high"
    strings:
        $proc_mount  = /mount\s+(-t\s+tmpfs\s+(-o\s+\S+\s+)?tmpfs|--bind\s+\S+|-o\s+bind\s+\S+)\s+['"]?\/proc\/[0-9${}a-zA-Z_]+/ nocase
        $pipe_sh     = /(mkfifo|mknod)\s+\/tmp\/\S+\s*;\s*(\/bin\/)?(ba)?sh/ nocase
        $implant_kw  = /(GHOST-SHELL|TIER-1\s+RED\s+TEAM|KALI-MASTER|systemd-resolved-updater)/ nocase
        $cron_tmp    = /(echo|cat|cp|install)[\s\S]{0,100}(\/etc\/cron|\/var\/spool\/cron)[\s\S]{0,100}\/(tmp|var\/tmp|dev\/shm)\/\S+/ nocase
        $rc_persist  = /(echo|cat|cp|install)[\s\S]{0,100}\/etc\/rc\.local[\s\S]{0,100}\/(tmp|var\/tmp|dev\/shm)\/\S+/ nocase
    condition:
        filesize < 2MB and (any of them)
}

rule Linux_Rootkit_LDPRELOAD_Hook_Artifact {
    meta:
        description = "Detects userland rootkit artifacts hooking libc functions via dynamic linker interception"
        severity = "alert"
        score = 90
        author = "Aether Security Team"
        mitre = "T1574.006"
        confidence = "high"
    strings:
        $preload_str = "/etc/ld.so.preload" ascii
        $dlsym_next  = "dlsym(RTLD_NEXT" ascii
        $hook_read   = "readdir" ascii
        $hook_open   = "fopen" ascii
        $hook_unlink = "unlink" ascii
        $hook_packet = "packet_rcv" ascii
    condition:
        uint32(0) == 0x464C457F and $preload_str and $dlsym_next and ($hook_read or $hook_open or $hook_unlink or $hook_packet)
}

rule Linux_Rootkit_Diamorphine_Reptile_Strings {
    meta:
        description = "Detects well-known Linux kernel rootkit artifacts and magic control strings"
        severity = "alert"
        score = 95
        author = "Aether Security Team"
        mitre = "T1014"
        confidence = "high"
    strings:
        $diamorph_1 = "diamorphine" nocase
        $diamorph_2 = "is_invisible" ascii
        $diamorph_3 = "hacked_kill" ascii
        $reptile_1  = "reptile" nocase
        $reptile_2  = "r00t_gr0up" ascii
        $reptile_3  = "reptile_cmd" ascii
    condition:
        filesize < 10MB and (2 of ($diamorph_*) or 2 of ($reptile_*))
}

rule Linux_Malware_Cryptominer_Stratum_Pool {
    meta:
        description = "Detects cryptocurrency mining configurations and Stratum mining pool endpoints"
        severity = "warning"
        score = 75
        author = "Aether Security Team"
        mitre = "T1496"
        confidence = "high"
    strings:
        $stratum_tcp = "stratum+tcp://" ascii
        $stratum_ssl = "stratum+ssl://" ascii
        $stratum_tls = "stratum+tls://" ascii
        $pool_1      = "pool.supportxmr.com" ascii
        $pool_2      = "mine.moneropool.com" ascii
        $pool_3      = "xmr.nanopool.org" ascii
        $xmrig_cfg   = "\"donate-level\":" ascii
        $xmrig_algo  = "\"randomx\"" ascii
    condition:
        filesize < 5MB and (($stratum_tcp or $stratum_ssl or $stratum_tls) and (any of ($pool_*) or $xmrig_cfg or $xmrig_algo))
}

rule Linux_Dropper_Remote_Pipe_Shell_Execution {
    meta:
        description = "Detects malicious shell droppers downloading and piping remote payloads directly into an execution shell"
        severity = "warning"
        score = 70
        author = "Aether Security Team"
        mitre = "T1105"
        confidence = "high"
    strings:
        $curl_sh = /curl\s+-[a-zA-Z0-9]*s[a-zA-Z0-9]*\s+https?:\/\/[^\s|;&]+\s*\|\s*(ba)?sh/ ascii
        $wget_sh = /wget\s+-[a-zA-Z0-9]*q[a-zA-Z0-9]*\s+-[a-zA-Z0-9]*O-\s+https?:\/\/[^\s|;&]+\s*\|\s*(ba)?sh/ ascii
        $curl_py = /curl\s+-[a-zA-Z0-9]*s[a-zA-Z0-9]*\s+https?:\/\/[^\s|;&]+\s*\|\s*python[23]?/ ascii
    condition:
        filesize < 1MB and (any of them)
}

rule Linux_Ransomware_Python_Locker {
    meta:
        description = "Detects Python ransomware scripts that traverse directories, encrypt files in place, and append ransomware extensions"
        severity = "alert"
        score = 95
        author = "Aether Security Team"
        mitre = "T1486"
        confidence = "high"
    strings:
        $f1 = "cryptography.fernet" nocase
        $f2 = "Fernet(" ascii
        $f3 = "AES.new" ascii
        $walk1 = "os.walk(" ascii
        $walk2 = "os.scandir(" ascii
        $walk3 = "rglob(" ascii
        $act1 = ".encrypt(" ascii
        $act2 = ".locked" ascii
        $act3 = ".enc" ascii
        $act4 = "os.remove(" ascii
        $act5 = "ransom" nocase
        $act6 = "DECRYPT" nocase
        $act7 = "RESCUE" nocase
        $act8 = "TARGET_DIR" ascii
    condition:
        filesize < 5MB and (any of ($f*)) and (any of ($walk*)) and (any of ($act*))
}

rule Linux_Malware_Data_Exfiltration_Client {
    meta:
        description = "Detects Python data exfiltration scripts harvesting files and transmitting archives over raw TCP/HTTP channels"
        severity = "alert"
        score = 90
        author = "Aether Security Team"
        mitre = "T1041"
        confidence = "high"
    strings:
        $sock1 = "socket.socket(" ascii
        $sock2 = "socket.create_connection(" ascii
        $sock3 = "urllib.request" ascii
        $sock4 = "requests.post(" ascii
        $walk1 = "os.walk(" ascii
        $walk2 = "os.scandir(" ascii
        $walk3 = "os.listdir(" ascii
        $comp1 = "zlib.compress" ascii
        $comp2 = "base64.b64encode" ascii
        $comp3 = "sendall(" ascii
        $comp4 = "json.dumps(" ascii
        $kw1 = "exfil" nocase
        $kw2 = "TARGET_DIR" ascii
        $kw3 = "harvest" nocase
    condition:
        filesize < 5MB and (any of ($sock*)) and (any of ($walk*)) and (any of ($comp*)) and (any of ($kw*))
}

rule Linux_Malware_Data_Exfiltration_Server {
    meta:
        description = "Detects C2 data exfiltration listener servers capturing and reconstructing stolen directory trees"
        severity = "warning"
        score = 75
        author = "Aether Security Team"
        mitre = "T1071.001"
        confidence = "high"
    strings:
        $sock1 = "socket.socket(" ascii
        $bind = ".bind(" ascii
        $listen = ".listen(" ascii
        $accept = ".accept(" ascii
        $kw1 = "exfil" nocase
        $kw2 = "tree.json" ascii
        $kw3 = "stolen" nocase
        $kw4 = "victim" nocase
        $kw5 = "zlib.decompress" ascii
        $kw6 = "b64decode" ascii
        $kw7 = "dump_payload" ascii
    condition:
        filesize < 5MB and ($sock1 and $bind and $listen and $accept) and (any of ($kw*))
}

rule Linux_Script_PowerShell_Encoded_Execution {
    meta:
        description = "Detects obfuscated PowerShell execution with Base64 encoded payload flags"
        severity = "alert"
        score = 85
        author = "Aether Security Team"
        mitre = "T1059.001"
        confidence = "high"
    strings:
        $ps1 = /(pwsh|powershell)(\.exe)?\s+.*-(e|enc|encodedcommand)\s+[A-Za-z0-9+\/=]{10,}/ nocase
    condition:
        filesize < 2MB and $ps1
}

rule Linux_Script_Cloud_Exfiltration_Tool {
    meta:
        description = "Detects automated cloud storage synchronization and exfiltration tools"
        severity = "warning"
        score = 80
        author = "Aether Security Team"
        mitre = "T1567.002"
        confidence = "medium"
    strings:
        $rclone    = /rclone\s+(copy|copyto|sync|move|rcat)\s+.*(\/etc\/|\/root\/|\/home\/|\.tar(\.(gz|bz2|xz))?|\.zip|\.7z|\.sql|\.kdbx|\.db)/ nocase
        $s5cmd     = /s5cmd\s+(cp|sync|cat)\s+.*(\/etc\/|\/root\/|\/home\/|\.tar(\.(gz|bz2|xz))?|\.zip|\.7z|\.sql|\.kdbx|\.db)/ nocase
        $mega      = /mega-(put|cmd|export)\s+.*(\/etc\/|\/root\/|\/home\/|\.tar(\.(gz|bz2|xz))?|\.zip|\.7z|\.sql|\.kdbx|\.db)/ nocase
        $aws       = /aws\s+s3\s+(cp|sync|mv)\s+.*(\/etc\/|\/root\/|\/home\/|\.tar(\.(gz|bz2|xz))?|\.zip|\.7z|\.sql|\.kdbx|\.db)/ nocase
        $gsutil    = /(gsutil|gcloud\s+storage)\s+(cp|rsync)\s+.*(\/etc\/|\/root\/|\/home\/|\.tar(\.(gz|bz2|xz))?|\.zip|\.7z|\.sql|\.kdbx|\.db)/ nocase
        $azcopy    = /azcopy\s+(copy|sync)\s+.*(\/etc\/|\/root\/|\/home\/|\.tar(\.(gz|bz2|xz))?|\.zip|\.7z|\.sql|\.kdbx|\.db)/ nocase
        $curl_post = /curl\s+.*(-T|--upload-file|-F)\s+.*https?:\/\/(transfer\.sh|file\.io|bashupload\.com|catbox\.moe|0x0\.st)/ nocase
    condition:
        filesize < 2MB and (any of them)
}

rule Linux_Persistence_Linker_Audit_Hijack {
    meta:
        description = "Detects dynamic linker audit or preload interface hijacking (LD_AUDIT / LD_PRELOAD / ld.so.preload)"
        severity = "alert"
        score = 85
        author = "Aether Security Team"
        mitre = "T1574.006"
        confidence = "high"
    strings:
        $ld_hook      = /(LD_AUDIT|LD_PRELOAD|LD_LIBRARY_PATH)\s*=/ nocase
        $preload_file = "/etc/ld.so.preload" ascii
        $audit_file   = "/etc/ld.so.audit" ascii
        $env_inject   = /Environment\s*=.*LD_(AUDIT|PRELOAD)/ nocase
    condition:
        filesize < 2MB and (any of them)
}

rule Linux_Persistence_PAM_Exec_Suspicious {
    meta:
        description = "Detects PAM authentication hooks executing scripts or binaries with elevated privileges in volatile paths"
        severity = "alert"
        score = 90
        author = "Aether Security Team"
        mitre = "T1556.004"
        confidence = "high"
    strings:
        $pam = /(pam_exec\.so|pam_script\.so)\s+.*(\/(tmp|var\/tmp|dev\/shm|root|home)|\/\.[a-zA-Z0-9_]+|\.(sh|py|pl)(\s|$)|seteuid)/ nocase
    condition:
        filesize < 1MB and $pam
}
`
