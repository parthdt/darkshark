#!/usr/bin/env python3

#imports
from scapy.all import *
from scapy.layers.http import *
import subprocess
import os
import glob
import sys
import re

#class for new interface
class newInterface:
	def __init__(self,name,ip,mac):
		self.name = name
		self.ip = ip
		self.mac = mac
	
	#print interface
	def print_interface(self):   
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
	#get default interface
	def default_interface(self): 
		return self.dface
	
	#to verify interface given by user.. return 1 if valid else 0
	def validate_interface(self,name):
		if(name==""):
			return 1
		flag = 0
		for i in self.interfaces:
			if(i.name == name):
				flag = 1
				break
		if(flag==0):
			return 0
		else:
			return 1
	# pretty print interfaces
	def print_interfaces(self):
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

#Function to validate a BPF, returns 1 if valid else 0
def validate_filter(filter):
	p = subprocess.Popen(['tcpdump','-i','eth0','-d',filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = p.communicate()
	if stderr:return 0
	else:return 1

#print introduction
def print_intro():
	os.system('clear')
	for i in range (130):
		print("-",end = "")
	logo = '''
	\t\t\t\t ___   _   ___ _  _____ _  _   _   ___ _  __
	\t\t\t\t|   \ /_\ | _ \ |/ / __| || | /_\ | _ \ |/ /
	\t\t\t\t| |) / _ \|   / ' <\__ \ __ |/ _ \|   / ' < 
	\t\t\t\t|___/_/ \_\_|_\_|\_\___/_||_/_/ \_\_|_\_|\_|
	\t\t\t\t\t\t\t\t\t     (v1.0)'''
                                            
	print(logo)
	for i in range (130):
		print("-", end = "")
	# print("\n\t\t\t\t\t__/\__ Welcome to the DARKSHARK (v1.0) __/\__")
	print("\n\nGet ready to dive in the world of packet sniffing with your new buddy DARKSHARK.")
	print("Developed with \u2764 by the three comrades:")
	print("\t-> Parth Thakker")
	print("\t-> Gaurav Bansal")
	print("\t-> Manas Ghai")
	print("\nSpecifications:-")
	print("------------------")
	print("\t-> Automatically Detect available network interfaces on the device with their IP and MAC addresses.")
	print("\t-> Shows all the TCP/IP stack layers of captured packets.")
	print("\t-> Supports a bunch of Berkley Packet Filters (BPFs) for smooth experience.")
	print("\t-> Comes with Regular Expression matching and Keyword searching during sniffing.")
	print("\t-> Supports logging of the sniffing summary.")
	for i in range (130):
		print("-", end = "")
	print("\n")
	
#print menu of available functionalities
def print_menu():
	menu = '''Select one of the following to continue :-
	1. List available interfaces
	2. List available BPFs
	3. Start packet sniffing
	4. Exit'''
	print(menu)

#option 1 of menu, listing available interfaces
def list_interfaces():
	interfaces.print_interfaces()
	
#option 2 of menu, giving a small tutorial on BPF's
def list_bpf():
	bpflist = '''Note: Berkeley Packet Filters are in lowercase.

	Some examples of BPF's are:

	1. To restrict to a particular protocol, just type in that protocol:
	Example:
	tcp
	icmp

	2. You can also filter out properties of that protocol, say the port number or the source/destination IP:
	Examples:
	tcp port 80 (to and fro port 80, HTTP)
	ip host 192.168.1.1 (host ip should be 192.168.1.1)
	tcp dst port 80(to port 80, HTTP)

	3. You can also combine multiple BPF's using 'and':
	Examples:
	icmp[icmptype] != icmp-echo and icmp[icmptype] != icmp-echoreply (basically means no ping packets)

	To know more about BPF syntax, visit this webpage:
	'https://biot.com/capstats/bpf.html'
	'''
	print(bpflist)

#option 3 of menu, capturing and sniffing packets
def capture_packets(filecounter):
	print("Starting Packet Sniffing: ")
	print("--------------------------------------")

	#Get the packetnumber
	packetNumber = 5
	while True:
		pn = input("Enter the number of packets to be sniffed: (Default is 5)")
		if not pn or int(pn)>0:
			break
		elif int(pn)<=0: print("Please enter a positive number.")
	packetNumber = int(pn) if pn else 5
		
	#Get the interface
	interface = ""
	while True:   	#get interface and validate
		interface = input("Enter the interface (leave blank for {}): ".format(interfaces.default_interface()))
		if(interfaces.validate_interface(interface) == 1):
			break
		else:
			print("Given Interface not found.. Wrong input! Enter again..")			   		
	actual_interface = interfaces.default_interface() if not interface else interface  
	
	#Get the BPF
	bpf = ""
	while True:
		bpf = input("Enter BPF (leave blank if none) ")
		if not bpf:
			break
		else:
			if validate_filter(bpf):break
			else:print("Invalid filter! Please enter a valid one.")

	#Get the regex to match in packet
	keyword = input("Enter a keyword/regex to be searched in the raw data (leave blank if none) ")
    
	print("Packets captured and the data: (timeout is 10 seconds)\n")
	p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn=lambda x : x.show(), lfilter = lambda x: re.search(keyword,str(x)), timeout = 10)

	#If packets are captured, print and store them
	if p:
		#folder for storing packet captures
		foldername = "captures/"
		
		#check if files exist in that folder
		list_of_files = glob.glob(foldername+"*")
		if list_of_files:
			latest_file = max(list_of_files, key=os.path.getctime)
			temp = latest_file[-6]

			#If there's a digit at that position, its most probably our file, so update the counter.
			if temp.isdigit():filecounter=int(temp)+1
			#Else remove all captures, start afresh, since there maybe a garbage file there.
			else:
				for f in list_of_files:
					os.remove(f)

		print("Summary of the packets captured:\n")
		print(p.nsummary())

		#Write the sniffed packets to the file
		filename = "packet_capture_" + str(filecounter) +".pcap"
		writer=PcapWriter(foldername+filename)
		writer.write(p)
		writer.flush()
		print("The packets captured are saved to {} in the captures folder.".format(filename))
		filecounter+=1

	#If no packets are captured in the timeout interval, print appropriate message.
	else:
	    if not bpf and not keyword:print("Timeout of 10 seconds reached, no packets sniffed.")
	    else:print("Timeout of 10 seconds reached, no packets sniffed corresponding to the keyword/filter.")
	 
	return filecounter

#main function
print_intro() #print introduction on console
interfaces = Interface() #initialize interfaces
filecounter = 1	#initialise counter variable for file

#If captures directory hasn't already been created, then create it.
if not os.path.exists("captures"):
	os.mkdir("captures")

#Main loop
while True: 
	print_menu() #display menu
	ch=0
	while True:  #get user input and validate
		a = input("Enter Sr No. of your choice: ")
		if(a == "1" or a == "2" or a == "3" or a == "4"):
			ch = int(a)
			break
		else:
			print("Invalid input! Please enter a valid one.")

	#Call function according to user choice
	if(ch == 1):
		os.system('clear')
		list_interfaces()
	elif(ch == 2):
		os.system('clear')
		list_bpf()
	elif(ch==3):
		os.system('clear')
		filecounter = capture_packets(filecounter)
	else:
		sys.exit("-"*130+"\n\t\t\tHope the DARKSHARK experience was smooth. Come back another time :)")
			
	#Prompt for staying in the program
	to_continue = input("Do you want to stay? (y/n): ")
	if to_continue is not ("y" or "Y"):
		sys.exit("-"*130+"\n\t\t\tHope the DARKSHARK experience was smooth. Come back another time :)")

	os.system('clear')
