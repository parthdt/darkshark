#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang

import sys

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
	\t\t\t\t\t\t\t\t\t     (v3.0)'''
                                            
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

def print_attacks_menu():
	print("It's time to launch attacks \N{fire} Kick off by choosing one of the following:- ")
	print("1. IP Spoofing")
	print("2. IP Smurf Attack")
	print("3. DNS Reflection Attack")
	print("4. DNS Amplification Attack")
	print("5. TCP SYN Flooding Attack")
	print("6. Ping of Death")
	print("7. Exit")

def print_bpf_list():
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

def print_exit_message():
	sys.exit("-"*130+"\n\t\t\tHope the DARKSHARK experience was smooth. Come back another time \N{shark}")

