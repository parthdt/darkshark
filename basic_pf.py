#!/usr/bin/env python3

from scapy.all import *
import sys

while True:
    print("Basic packet sniffer!")
    packetNumber = int(input("Enter the number of packets to be sniffed: "))
    interface = input("Enter the interface: (leave blank if no input.) ")
    actual_interface = "eth0" if interface == "" else interface
    bpf = input("Enter BPF (leave blank if none.) ")
    print("Packets captured and the data:\n")
    p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn = lambda x: x.show())
    print("Summary of the packets captured:\n\n")
    print(p.nsummary())
    

    to_continue = input("Do you want to sniff more? (y/n)")

    if to_continue is not ("y" or "Y"):
        sys.exit(0)



