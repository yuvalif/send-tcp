# send-tcp
Building TCP/IP packet from commandline using pcap.

Build: gcc -Wall -o send_tcp send_tcp.c -lpcap

Usage: sudo ./send_tcp -i \<interface> -m \<dst-mac-address> -s \<src-ipv4-address>:\<port> -d \<dst-ipv4-address>:\<port> \[-f \<tcp-flag>] \[-q \<tcp-seq-num>] \[-v \<vlan-tag>]

