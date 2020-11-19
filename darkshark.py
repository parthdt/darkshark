#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang.
#Group- Parth,Gaurav,Manas

#imports
import os
from Interfaces import *
from GUI import *
from Sniffer import *
#from Helpers import *
from Attacks import *

#main function
print_intro() #print introduction on console
filecounter = 1	#initialise counter variable for file
counter = 1  #packet print counter
interfaces = Interface() #initialize interfaces

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
		#option 1 of menu, listing available interfaces, is interfaces.print_interfaces from 'Interfaces.py'
		interfaces.print_interfaces()
	elif(ch == 2):
		os.system('clear')
		#option 2 of menu is print_bpf_list() from 'GUI.py'
		print_bpf_list()
	elif(ch==3):
		os.system('clear')
		#option 3 of menu, capturing and sniffing packets, it is capture_packets() from 'Sniffer.py'
		filecounter = capture_packets(filecounter)
	elif(ch==4):
		os.system('clear')
		#option 4 of menu: launch attacks, is launch_attacks() from 'Attacks.py'
		launch_attacks()
	else:
		print_exit_message()
			
	#Prompt for staying in the program
	to_continue = input("Do you want to stay? (y/n): ")
	if to_continue is not ("y" or "Y"):
		print_exit_message()

	os.system('clear')

