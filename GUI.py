#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang

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
