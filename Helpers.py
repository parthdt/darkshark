#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang

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
