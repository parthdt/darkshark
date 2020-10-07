#!/usr/bin/env python3

from scapy.all import *
import sys

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
		c=1
		for i in self.interfaces:
			if(self.dface == i.name):
				print("Interface " + str(c) + " (Default Interface) :-")
			else:
				print("Interface " + str(c) + " :-")
			print("--------------------------------------")
			i.print_interface()
			c = c+1
			print()
	
#print introduction
def print_intro():
	print("Basic packet sniffer!")
	#print group members
	#functionality as menu : list interfaces, 
	#give a good look

while True:
    i = Interface()
    print(i.default_interface())
   	i.print_interfaces()  #giving identation error
    packetNumber = int(input("Enter the number of packets to be sniffed: "))
    interface = input("Enter the interface: (leave blank if no input.) ")
    actual_interface = i if interface == "" else interface
    bpf = input("Enter BPF (leave blank if none.) ")
    print("Packets captured and the data:\n")
    p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn = lambda x: x.show())
    print("Summary of the packets captured:\n\n")
    print(p.nsummary())
    

    to_continue = input("Do you want to sniff more? (y/n)")

    if to_continue is not ("y" or "Y"):
        sys.exit(0)
