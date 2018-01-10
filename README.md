# send-tcp
Building TCP/IP packet from commandline using pcap.

Build: `gcc -Wall -o send-tcp send-tcp.c -lpcap`

Usage: `sudo ./send-tcp -i \<interface> -m \<dst-mac-address> -s \<src-ipv4-address>:\<port> -d \<dst-ipv4-address>:\<port> \[-f \<tcp-flag>] \[-q \<tcp-seq-num>] \[-v \<vlan-tag>]`

