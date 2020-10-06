#!/usr/bin/env python3

from scapy.all import *
import sys

while True:
    print("Basic packet sniffer!")
    packetNumber = input("Enter the number of packets to be sniffed: ")
    packetNumber = 100 if not packetNumber else int(packetNumber)
    interface = input("Enter the interface: (leave blank if no input.) ")
    actual_interface = "eth0" if not interface else interface
    bpf = input("Enter BPF (leave blank if none.) ")
    keyword = input("Enter a keyword to be searched in the raw data (leave blank if none). ")
    print("Packets captured and the data:\n")
    p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn=lambda x: x.show(), lfilter = lambda x: keyword in str(x))
    print("Summary of the packets captured:\n\n")
    print(p.show())
    

    to_continue = input("Do you want to sniff more? (y/n)")

    if to_continue is not ("y" or "Y"):
        sys.exit(0)



