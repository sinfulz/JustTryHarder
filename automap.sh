//can't remember where I got this script from, let me know if it was you.

#!/bin/bash

for line in $(cat ip.txt); do
	mkdir $line;
	mkdir ./$line/screenshots
	nmap -sC -sV -p- -o ./$line/Full-TCP $line -Pn --min-rate 2000
done;
