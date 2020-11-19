#!/usr/bin/env python3

#Keep above line as first line always! Its a shebang

from Helpers import *
from Interfaces import *
import os
import glob
import re

#pretty print packet
def print_packet(packet):
	global counter
	print("Packet " + str(counter) + ":-")
	print("-"*15)
	packet.show()
	counter += 1

def capture_packets(filecounter):
    #If captures directory hasn't already been created, then create it.
    if not os.path.exists("captures"):
	    os.mkdir("captures")

    interfaces = Interface() #initialize interfaces
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
