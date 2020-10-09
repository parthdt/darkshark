#!/usr/bin/env python3

from scapy.all import *
from scapy.layers.http import *
import sys
import re

#class for new interface
class newInterface:
	def __init__(self,name,ip,mac):
		self.name = name
		self.ip = ip
		self.mac = mac
	
	def print_interface(self):   #print interface
		print("Name: " + self.name)
		print("IP Address: " + self.ip)
		print("MAC Address: " + self.mac)

#general class for interfaces
class Interface:
	def __init__(self):
		self.dface = conf.iface	
		self.interfaces = []
		x = get_if_list()
		if(len(x)==0):
			print("No interface detected!")
			sys.exit(0)
		for i in x:
			interface = newInterface(i,get_if_addr(i),get_if_hwaddr(i))
			self.interfaces.append(interface)	
	
	def default_interface(self):  #get default interface
		return self.dface
	
	def print_interfaces(self):   # pretty print interfaces
		print("The Interfaces available are:")
		for c,i in enumerate(self.interfaces):
			if(self.dface == i.name):
				print("Interface " + str(c) + " (Default Interface) :-")
			else:
				print("Interface " + str(c) + " :-")
			print("--------------------------------------")
			i.print_interface()
			# c = c+1
			print()


def print_packet(packet,counter):
	print("Packet ",counter)
	print("--------------------------------------")
	packet.show()
	counter+=1

#print introduction
def print_intro():
	print("Basic packet sniffer!")
	print("--------------------------------------\n")
	#print group members
	#functionality as menu :
    # 1. list interfaces,
    # 2. show different bpf's, 
    # 3. sniff packets, give options to save to a file
    # 4. show menu again
    # 5. ?
	#give a good look

counter=1
print_intro()

while True:
    i = Interface()
    # print("Default interface is:",i.default_interface(), "\n") #Commenting out as default is shown again below.
    i.print_interfaces()
    packetNumber = input("Enter the number of packets to be sniffed: ")
    packetNumber = 100 if not packetNumber else int(packetNumber)

    interface = input("Enter the interface: (leave blank for default) ")
    actual_interface = "eth0" if not interface else interface

    bpf = input("Enter BPF (leave blank if none) ")
    keyword = input("Enter a keyword to be searched in the raw data (leave blank if none) ")
    
    print("Packets captured and the data: (timeout is 10 seconds)\n")
    p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn=lambda x : x.show(), lfilter = lambda x: re.search(keyword,str(x)), timeout = 10
    if p:
        print("Summary of the packets captured:\n")
        print(p.nsummary())
    else:
        if not bpf and not keyword:print("No packets sniffed, timeout reached.")
        else:print("No packets sniffed corresponding to the bpf/keyword, timeout reached.")

    to_continue = input("Do you want to sniff more? (y/n)")
    if to_continue is not ("y" or "Y"):
        sys.exit(0)
