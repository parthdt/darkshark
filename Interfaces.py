#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang
from scapy.all import *

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
			if i=="sit0":continue		#For WSL2, ignore invalid interface
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