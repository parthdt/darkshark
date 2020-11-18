#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang.
#Group- Parth,Gaurav,Manas

#imports
from scapy.all import *
from scapy.layers.http import *
import subprocess
import os
import glob
import sys
import re
import ipaddress
from Interfaces import *
from GUI import *
# from Helpers import *
from Attacks import *

# option 1 of menu, listing available interfaces
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

#pretty print packet
def print_packet(packet):
	global counter
	print("Packet " + str(counter) + ":-")
	print("-"*15)
	packet.show()
	counter += 1

#option 3 of menu, capturing and sniffing packets
def capture_packets(filecounter):
	print("Starting Packet Sniffing: ")
	print("--------------------------------------")
	#reset packet print counter
	global counter
	counter = 1
	#Get the packetnumber to capture
	packetNumber = get_packetCount_capture()
		
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
		bpf = input("Enter BPF (leave blank if none): ")
		if not bpf:
			break
		else:
			if validate_filter(bpf):break
			else:print("Invalid filter! Please enter a valid one.")

	#Get the regex to match in packet
	keyword = input("Enter a keyword/regex to be searched in the raw data (leave blank if none): ")
    
	print("\nPackets captured and the data is: (timeout is 20 seconds)")
	p = sniff(count = packetNumber, iface = actual_interface, filter = bpf, prn = print_packet, lfilter = lambda x: re.search(keyword,str(x)), timeout = 20)

	#If packets are captured, print and store them
	if p:
		#folder for storing packet captures
		foldername = "captures/"
		
		#check if files exist in that folder
		list_of_files = glob(foldername+"*")
		if list_of_files:
			latest_file = max(list_of_files, key=os.path.getctime)
			temp = latest_file[-6]

			#If there's a digit at that position, its most probably our file, so update the counter.
			if temp.isdigit():filecounter=int(temp)+1
			#Else remove all captures, start afresh, since there maybe a garbage file there.
			else:
				for f in list_of_files:
					os.remove(f)

		print("Summary of the packets captured:")
		print("-"*40)
		p.nsummary()
		print()

		#Write the sniffed packets to the file
		filename = "packet_capture_" + str(filecounter) +".pcap"
		writer=PcapWriter(foldername+filename)
		writer.write(p)
		writer.flush()
		print("The packets captured are saved to {} in the captures folder.".format(filename))
		filecounter+=1

	#If no packets are captured in the timeout interval, print appropriate message.
	else:
	    if not bpf and not keyword:print("Timeout reached, no packets sniffed.")
	    else:print("Timeout seconds reached, no packets sniffed corresponding to the keyword/filter.")
	 
	return filecounter

#option 4 of menu: launch attacks
def launch_attacks():
	print("It's time to launch attacks \N{fire} Kick off by choosing one of the following:- ")
	print("1. IP Spoofing")
	print("2. IP Smurf Attack")
	print("3. DNS Reflection Attack")
	print("4. DNS Amplification Attack")
	print("5. TCP SYN Flooding Attack")
	print("6. Ping of Death")
	print("7. Exit")
	ch=0
	while True:  #get user input and validate
		a = input("Enter Sr No. of your choice: ")
		if(a == "1" or a == "2" or a == "3" or a == "4" or a == "5" or a=="6" or a=="7"):
			ch = int(a)
			break
		else:
			print("Invalid input! Please enter a valid one.")
	#Call function according to user choice
	if(ch == 1):
		os.system('clear')
		ip_spoofing()
	elif(ch == 2):
		os.system('clear')
		ip_smurf_attack()
	elif(ch==3):
		os.system('clear')
		dns_reflection_attack()
	elif(ch==4):
		os.system('clear')
		dns_amplification_attack()
	elif(ch==5):
		os.system('clear')
		tcp_synflood_attack()
	elif(ch==6):
		os.system('clear')
		ping_of_death()
	else:
		sys.exit("-"*130+"\n\t\t\tHope the DARKSHARK experience was smooth. Come back another time \N{shark}")

#main function
print_intro() #print introduction on console
interfaces = Interface() #initialize interfaces
filecounter = 1	#initialise counter variable for file
counter = 1  #packet print counter

#If captures directory hasn't already been created, then create it.
if not os.path.exists("captures"):
	os.mkdir("captures")

#Main loop
while True: 
	print_menu() #display menu
	ch=0
	while True:  #get user input and validate
		a = input("Enter Sr No. of your choice: ")
		if(a == "1" or a == "2" or a == "3" or a == "4" or a == "5"):
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
	elif(ch==4):
		os.system('clear')
		launch_attacks()
	else:
		sys.exit("-"*130+"\n\t\t\tHope the DARKSHARK experience was smooth. Come back another time \N{shark}")
			
	#Prompt for staying in the program
	to_continue = input("Do you want to stay? (y/n): ")
	if to_continue is not ("y" or "Y"):
		sys.exit("-"*130+"\n\t\t\tHope the DARKSHARK experience was smooth. Come back another time \N{shark}")

	os.system('clear')

