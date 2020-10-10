#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.http import *
import subprocess
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
		self.dface = conf.iface	  #default interface
		self.interfaces = []
		x = get_if_list()     #getting available interfaces information
		if(len(x)==0):
			print("No interface detected!")
			sys.exit(0)
		for i in x:
			interface = newInterface(i,get_if_addr(i),get_if_hwaddr(i))
			self.interfaces.append(interface)	
	
	def default_interface(self):  #get default interface
		return self.dface
		
	def validate_interface(self,name):  #to verify interface given by user.. return 1 if valid else 0
		if(name==""):
			return 1
		flag = 0
		for i in self.interfaces:
			if(i.name == name):
				flag = 1
				break
		if(flag==0):
			#print("Given Interface not found.. Wrong input!")
			return 0
		else:
			return 1
	
	def print_interfaces(self):   # pretty print interfaces
		print("The Interfaces detected on the device are:")
		print()
		for c,i in enumerate(self.interfaces):
			if(self.dface == i.name):
				print("Interface " + str(c) + " (Default Interface) :-")
			else:
				print("Interface " + str(c) + " :-")
			print("--------------------------------------")
			i.print_interface()
			print()

def validate_filter(filter):
	p = subprocess.Popen(['tcpdump','-i','eth0','-d',filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = p.communicate()
	if stderr:return 0
	else:return 1


#print introduction function
def print_intro():
	print()
	for i in range (110):
		print("-",end = "")
	print()
	print("\t\t\t__/\__ Welcome to the DARKSHARK (v1.0) __/\__")
	for i in range (110):
		print("-", end = "")
	print()
	print("Get ready to dive in the world of packet sniffing with your new buddy DARKSHARK. Developed by 3 comrades:")
	print("\t-> Parth Thakker")
	print("\t-> Gaurav Bansal")
	print("\t-> Manas Ghai")
	print("Specifications:-")
	print("------------------")
	print("-> Automatically Detect available network interfaces on the device with their IP and MAC addresses.")
	print("-> Shows all the TCP/IP stack layers of captured packets.")
	print("-> Supports a bunch of Berkley Packet Filters (BPFs) for smooth experience.")
	print("-> Comes with Regular Expression matching and Keyword searching during sniffing.")
	print("-> Supports logging of the sniffing summary.")
	for i in range (110):
		print("-", end = "")
	print()

#pretty print packet
counter=1
def print_packet(packet,counter):
	print("Packet ",counter)
	print("--------------------------------------")
	packet.show()
	counter+=1
		
#print functionality menu
def print_menu():
	print("Select one of the following to start :-")
	print("1. List available interfaces")
	print("2. List available BPFs")
	print("3. Start packet sniffing")

#option 1 of menu
def list_interfaces():
	interfaces.print_interfaces()
	
#option 2 of menu
def list_bpf():     #complete this
	print("Available BPFs are: ")
	#print("-> tcp")etc.
	print()
	
#option 3 of menu
def capture_packets():   #complete this and add output writing in file
	print("Starting Packet Sniffing: ")
	print("--------------------------------------")

	#shift sniffing code here
	packetNumber = input("Enter the number of packets to be sniffed: (Default is 5)")
	packetNumber = 5 if not packetNumber else int(packetNumber)
	
	interface = ""
	while True:   	#get interface and validate
		interface = input("Enter the interface (leave blank for {}): ".format(interfaces.default_interface()))
		if(interfaces.validate_interface(interface) == 1):
			break
		else:
			print("Given Interface not found.. Wrong input! Enter again..")			   		
	actual_interface = interfaces.default_interface() if not interface else interface  
	
	bpf = ""
	while True:
		bpf = input("Enter BPF (leave blank if none) ")
		if not bpf:
			break
		else:
			if validate_filter(bpf):break
			else:print("Invalid filter! Please enter a valid one.")

	keyword = input("Enter a keyword to be searched in the raw data (leave blank if none) ")
    
	print("Packets captured and the data: (timeout is 10 seconds)\n")
	p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn=lambda x : x.show(), lfilter = lambda x: re.search(keyword,str(x)), timeout = 10)
	if p:
		print("Summary of the packets captured:\n")
		print(p.nsummary())
	else:
	    if not bpf and not keyword:print("No packets sniffed, timeout reached.")
	    else:print("No packets sniffed corresponding to the bpf/keyword, timeout reached.")
	 
	 
#main function
print_intro() #print introduction on console
interfaces = Interface() #initialize interfaces
while True:  
	print_menu() #display menu
	ch=0
	while True:  #get user input and validate
		a = input("Enter Sr No. of your choice: ")
		if(a == "1" or a == "2" or a == "3"):
			ch = int(a)
			break
		else:
			print("Wrong input!! Enter again..")
	print("----------------------------------------------------------------------")
	if(ch == 1):
		list_interfaces()
	elif(ch == 2):
		list_bpf()
	else:
		capture_packets()
			
	to_continue = input("Do you want to stay? (y/n): ")
	if to_continue is not ("y" or "Y"):
		print()
		print("\t\t\tThank You.. :)")
		sys.exit(0)
	print("----------------------------------------------------------------------")
