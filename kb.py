"""
kb.py -- Knowledge base for reconote.

Maps ports/services to plain-English explanations and suggested
next-step enumeration commands/tools. This is written for CTF /
TryHackMe / authorized lab use -- it names standard enumeration
tooling and methodology, not exploit code.
"""

# Each entry:
#   name: short label
#   what: what the service is
#   why: why it matters from an attacker/CTF perspective
#   next: list of concrete next-step commands/tools (as strings, with
#         {target} and {port} placeholders you can .format() in)
KB = {
    21: {
        "name": "FTP",
        "what": "File Transfer Protocol -- often used to move files, sometimes left with weak auth.",
        "why": "Anonymous FTP logins are a classic CTF foothold. Writable FTP dirs can be used to plant files a web app might read.",
        "next": [
            "ftp {target}  (try user: anonymous, any password)",
            "nmap -p {port} --script ftp-anon,ftp-syst,ftp-vsftpd-backdoor {target}",
            "Check the banner for a version string, then searchsploit '<product> <version>'",
        ],
    },
    22: {
        "name": "SSH",
        "what": "Secure Shell -- remote login/admin.",
        "why": "Rarely exploitable directly, but the banner reveals OS/version, and it's a common target for credential reuse once you find creds elsewhere.",
        "next": [
            "ssh -v {target}  (banner grab / algorithm negotiation)",
            "If you find creds elsewhere: ssh user@{target}",
            "searchsploit openssh <version>  (check for known CVEs matching the banner)",
        ],
    },
    23: {
        "name": "Telnet",
        "what": "Unencrypted remote terminal access.",
        "why": "Plaintext creds over the wire; still shows up on routers/IoT/legacy boxes in labs.",
        "next": [
            "telnet {target} {port}",
            "nmap -p {port} --script telnet-encryption,banner {target}",
        ],
    },
    25: {
        "name": "SMTP",
        "what": "Mail transfer service.",
        "why": "VRFY/EXPN can enumerate valid usernames; banner often leaks mail server software/version.",
        "next": [
            "nmap -p {port} --script smtp-commands,smtp-enum-users {target}",
            "nc {target} {port}  then try: VRFY root",
        ],
    },
    53: {
        "name": "DNS",
        "what": "Domain Name System.",
        "why": "Zone transfers (AXFR) can dump every hostname in a domain -- huge for mapping internal names.",
        "next": [
            "dig axfr @{target} <domain>",
            "dnsrecon -d <domain> -n {target}",
            "nmap -p {port} --script dns-zone-transfer {target}",
        ],
    },
    80: {
        "name": "HTTP",
        "what": "Web server.",
        "why": "The biggest attack surface on most boxes: hidden dirs, outdated CMS, source-code leaks, LFI/SQLi/etc.",
        "next": [
            "curl -sI http://{target}:{port}/  (headers, server banner)",
            "whatweb http://{target}:{port}/",
            "gobuster dir -u http://{target}:{port}/ -w /usr/share/wordlists/dirb/common.txt",
            "nikto -h http://{target}:{port}/",
            "Check /robots.txt, view-source, and any login forms for default creds",
        ],
    },
    110: {
        "name": "POP3",
        "what": "Mail retrieval protocol.",
        "why": "Plaintext auth by default; valid mailboxes = valid usernames elsewhere.",
        "next": [
            "nc {target} {port}  then: USER test / PASS test",
            "nmap -p {port} --script pop3-capabilities {target}",
        ],
    },
    111: {
        "name": "rpcbind",
        "what": "RPC portmapper -- tells you which RPC services (often NFS) are running and on what port.",
        "why": "First step to finding an NFS export you can mount.",
        "next": [
            "rpcinfo -p {target}",
            "showmount -e {target}",
        ],
    },
    135: {
        "name": "MSRPC",
        "what": "Windows RPC endpoint mapper.",
        "why": "Used to enumerate other Windows RPC services; a strong signal the box is Windows.",
        "next": [
            "rpcdump.py {target}  (impacket)",
            "nmap -p {port} --script msrpc-enum {target}",
        ],
    },
    139: {
        "name": "NetBIOS/SMB",
        "what": "Legacy SMB/NetBIOS session service.",
        "why": "Same value as 445 -- shares, usernames, OS/version fingerprinting.",
        "next": [
            "smbclient -L //{target}/ -N",
            "enum4linux -a {target}",
        ],
    },
    143: {
        "name": "IMAP",
        "what": "Mail retrieval protocol.",
        "why": "Plaintext auth by default; can leak valid usernames.",
        "next": [
            "nmap -p {port} --script imap-capabilities {target}",
            "curl -k 'imap://{target}'",
        ],
    },
    161: {
        "name": "SNMP",
        "what": "Network device monitoring/management, usually over UDP.",
        "why": "Default community strings ('public'/'private') often expose full system info, routes, even process lists.",
        "next": [
            "snmpwalk -c public -v1 {target}",
            "onesixtyone -c community-strings.txt {target}",
        ],
    },
    389: {
        "name": "LDAP",
        "what": "Directory service, common on Active Directory domain controllers.",
        "why": "Anonymous bind can dump the whole directory: users, groups, policy -- gold for AD boxes.",
        "next": [
            "ldapsearch -x -H ldap://{target} -s base",
            "windapsearch.py --dc-ip {target} -u '' -m users",
        ],
    },
    443: {
        "name": "HTTPS",
        "what": "Web server over TLS.",
        "why": "Same as HTTP, plus the TLS cert itself often leaks hostnames (SANs) useful for vhost enumeration.",
        "next": [
            "curl -skI https://{target}:{port}/",
            "openssl s_client -connect {target}:{port}  (read the cert SANs)",
            "gobuster vhost -u https://{target}:{port}/ -w subdomains.txt",
        ],
    },
    445: {
        "name": "SMB",
        "what": "Windows file/print sharing.",
        "why": "One of the highest-value ports in CTFs: null-session enumeration, shares, usernames, and a long history of RCE bugs (EternalBlue, SMBGhost, etc.).",
        "next": [
            "smbclient -L //{target}/ -N",
            "enum4linux -a {target}",
            "nmap -p {port} --script smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln* {target}",
            "crackmapexec smb {target}",
        ],
    },
    512: {"name": "rexec", "what": "Legacy remote execution.", "why": "Old, often misconfigured; worth a banner check.", "next": ["nc {target} {port}"]},
    513: {"name": "rlogin", "what": "Legacy remote login (trusts .rhosts).", "why": "Can allow passwordless login if .rhosts trust is misconfigured.", "next": ["rlogin -l root {target}"]},
    514: {"name": "rsh/syslog", "what": "Legacy remote shell or syslog.", "why": "Same trust issues as rlogin if it's rsh.", "next": ["nc {target} {port}"]},
    993: {
        "name": "IMAPS",
        "what": "IMAP over TLS.",
        "why": "Same value as 143, encrypted transport.",
        "next": ["openssl s_client -connect {target}:{port}"],
    },
    995: {
        "name": "POP3S",
        "what": "POP3 over TLS.",
        "why": "Same value as 110, encrypted transport.",
        "next": ["openssl s_client -connect {target}:{port}"],
    },
    1433: {
        "name": "MSSQL",
        "what": "Microsoft SQL Server.",
        "why": "Default/weak sa creds are common in labs; xp_cmdshell can turn DB access into RCE.",
        "next": [
            "python3 mssqlclient.py user@{target}  (impacket)",
            "nmap -p {port} --script ms-sql-info,ms-sql-empty-password {target}",
        ],
    },
    1521: {
        "name": "Oracle TNS",
        "what": "Oracle database listener.",
        "why": "SID enumeration + default creds (scott/tiger, system/manager) are common CTF wins.",
        "next": [
            "odat.py sidguesser -s {target}",
            "tnscmd10g version -h {target}",
        ],
    },
    2049: {
        "name": "NFS",
        "what": "Network File System.",
        "why": "Misconfigured exports let you mount remote filesystems directly -- sometimes with root read/write.",
        "next": [
            "showmount -e {target}",
            "mount -t nfs {target}:/export /mnt/target",
        ],
    },
    3306: {
        "name": "MySQL",
        "what": "MySQL/MariaDB database.",
        "why": "Weak/blank root passwords are common in vulnerable-by-design labs; can lead to file read/write via LOAD_FILE/INTO OUTFILE.",
        "next": [
            "mysql -h {target} -u root -p",
            "nmap -p {port} --script mysql-info,mysql-empty-password,mysql-enum {target}",
        ],
    },
    3389: {
        "name": "RDP",
        "what": "Windows Remote Desktop.",
        "why": "Credential target; also had major RCE bugs (BlueKeep). Version/security-layer info leaks from the handshake.",
        "next": [
            "xfreerdp /v:{target} /u:<user>",
            "nmap -p {port} --script rdp-enum-encryption,rdp-vuln-ms12-020 {target}",
        ],
    },
    5432: {
        "name": "PostgreSQL",
        "what": "PostgreSQL database.",
        "why": "Default 'postgres' account with weak/no password is common; COPY ... TO/FROM PROGRAM can give command execution.",
        "next": [
            "psql -h {target} -U postgres",
            "nmap -p {port} --script pgsql-brute {target}",
        ],
    },
    5900: {
        "name": "VNC",
        "what": "Remote desktop / screen sharing.",
        "why": "Frequently run with no password or a trivial one in labs.",
        "next": [
            "vncviewer {target}::{port}",
            "nmap -p {port} --script vnc-info,realvnc-auth-bypass {target}",
        ],
    },
    5985: {
        "name": "WinRM",
        "what": "Windows Remote Management (HTTP).",
        "why": "If you have creds/hashes, WinRM is often the cleanest way to get a shell on a Windows box.",
        "next": [
            "evil-winrm -i {target} -u <user> -p <pass>",
            "crackmapexec winrm {target}",
        ],
    },
    5986: {
        "name": "WinRM (HTTPS)",
        "what": "WinRM over TLS.",
        "why": "Same as 5985, encrypted transport.",
        "next": ["evil-winrm -i {target} -u <user> -p <pass> -S"],
    },
    6379: {
        "name": "Redis",
        "what": "In-memory key/value store.",
        "why": "Unauthenticated by default in many misconfigured setups; can be abused to write an SSH key or cron job for RCE.",
        "next": [
            "redis-cli -h {target}",
            "nmap -p {port} --script redis-info {target}",
        ],
    },
    8000: {"name": "HTTP-alt", "what": "Alternate web port.", "why": "Same as 80 -- often a dev server or admin panel.", "next": ["curl -sI http://{target}:{port}/", "gobuster dir -u http://{target}:{port}/ -w /usr/share/wordlists/dirb/common.txt"]},
    8080: {"name": "HTTP-alt", "what": "Alternate web port, common for proxies/app servers (Tomcat, Jenkins, etc.).", "why": "Frequently hosts admin consoles with default creds (Tomcat manager, Jenkins script console).", "next": ["curl -sI http://{target}:{port}/", "whatweb http://{target}:{port}/", "gobuster dir -u http://{target}:{port}/ -w /usr/share/wordlists/dirb/common.txt"]},
    8009: {
        "name": "AJP",
        "what": "Apache JServ Protocol, used between web servers and Tomcat.",
        "why": "Ghostcat (CVE-2020-1938) allowed file read/RCE via AJP; worth flagging if Tomcat is present.",
        "next": ["nmap -p {port} --script ajp-methods {target}"],
    },
    8443: {"name": "HTTPS-alt", "what": "Alternate HTTPS port.", "why": "Same as 443, often admin panels.", "next": ["curl -skI https://{target}:{port}/"]},
    9200: {
        "name": "Elasticsearch",
        "what": "Search/indexing engine with an HTTP API.",
        "why": "Historically shipped with no auth by default; the whole index is often readable/writable over plain HTTP.",
        "next": [
            "curl http://{target}:{port}/_cat/indices?v",
            "curl http://{target}:{port}/_search?pretty",
        ],
    },
    27017: {
        "name": "MongoDB",
        "what": "NoSQL database.",
        "why": "Historically bound with no auth by default -- direct data dump possible.",
        "next": [
            "mongo --host {target}",
            "nmap -p {port} --script mongodb-databases,mongodb-info {target}",
        ],
    },
}

GENERIC = {
    "name": "Unknown/uncommon service",
    "what": "An open port without a well-known mapping in this tool's knowledge base.",
    "why": "Worth a manual look -- the banner or a protocol-aware scan may reveal what it is.",
    "next": [
        "nc -nv {target} {port}  (see if it prints a banner)",
        "nmap -sV -p {port} {target}  (service/version fingerprinting)",
        "searchsploit <whatever the banner names>",
    ],
}


def lookup(port: int, service_hint: str = "") -> dict:
    """Return the KB entry for a port, falling back to a generic entry."""
    entry = KB.get(port)
    if entry:
        return entry
    return GENERIC
