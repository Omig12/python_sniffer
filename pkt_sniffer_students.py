###############################################################################
#
# Author: Jose Ortiz-Ubarri, Ph.D.
# Computer Science department - UPR
#
# Project template.  Implementation of a simple packet sniffer/classifier
# Your goal is to implement a packet counter of protocols.  You will modify the
# following code such that you have a counter of protocols over Ethernet: IP,
# ARP, Others, and a counter of protocols over IP: TCP, UDP, ICMP, Others.
# Finally a counter for the application protocols HTTP, SSH and, DNS.
# The sniffer continuously sniffs packets from the network until the program 
# is killed with CTRL-C.  When the program receives the kill signal your
# program must STOP and display the results.
##############################################################################

import socket, binascii, struct
import time
import textwrap
import sys
import traceback

# Define protocols constants.  You should have one for each IP, ARP, TCP, UDP, 
# ICMP
PACKETS = 0

ETH_COUNT = {"IP" : 0, "ARP" : 0, "Others" : 0}
TRANS_COUNT= {"TCP": 0, "UDP" : 0, "ICMP" : 0, "Others": 0}
APP_COUNT = {"HTTP": 0, "SSH": 0, "DNS": 0, "SMTP" : 0, "Others": 0}
Proto_DIC = {"1":"ICMP","6":"IP_TCP","8":"ETH_IP","17":"IP_UDP","54":"ARP","1544":"ETH_ARP"}
Mesg_DIC = { "0": "Echo Reply", "3":"Destination Unreachable","4":"Source Quench","5":"Redirect","8":"Echo","11":"Time Exceeded","12":"Parameter Problem","13":"Timestamp","14":"Timestamp Reply", "15":"Information Request", "16":"Information Reply"}
App_DIC = {"HTTP": 80, "HTTPS": 443, "SSH": 22, "SMTP" : 25,  "DNS": 53}

ICMP = 1
IP_TCP = 6
ETH_IP = 8
IP_UDP = 17
ARP = 54
ETH_ARP = 1544 

# Util function.  Do not modify.
def format(a):
	return "%.2x" % ord(a)

# Util function to format the MAC Addresses.  Do not modify.
def mac(address):
	return (':'.join(map(format, address))).upper()


# Funtion that receives the ethernet header of a packet and returns
# the source and destination MAC addresses and the protocol over eth. 
def getEthernetFrame(ethHeader):

	smac, dmac, proto = struct.unpack('!6s6sH', ethHeader)

	return mac(smac), mac(dmac), socket.htons(proto)

# Funtion that receives the IP header of a packet and returns
# the source and dst IP addresses and the protocol over IP.
def getIPInfo(ipHeader):
	
	iph = struct.unpack('!BBHHHBBH4s4s', ipHeader)

	return str(socket.inet_ntoa(iph[8])), str(socket.inet_ntoa(iph[9])), iph[6]

# Function that receives the transport header (TCP/UDP) header and returns
# the source and destionation port
def getICMPInfo(ICMPHeader):
	#Fill in start
	#Fetch the ICMP header from the IP packet
	TYPE, CODE, CHECKSUM = struct.unpack("!BBH", ICMPHeader)
	return TYPE, CODE, CHECKSUM

# Function that receives the transport header (TCP/UDP) header and returns
# the source and destionation port
def getHTTPInfo(ipHeader):
	#Fill in start
	#Fetch the ICMP header from the IP packet
	transh = struct.unpack('!HHLLBBHHH' , ipHeader)
	return 'Sequence Number :', str(transh[2]), '\nAcknowledgement :', str(transh[3]), '\nTCP header length :', str(transh[4])

# Function that receives the transport header (TCP/UDP) header and returns
# the source and destionation port
def getPorts(tcHeader):

	# Missing code here
	# Extract source and destination port
	tcph = struct.unpack('!HHLLBBHHH',tcHeader)
	sport, dport = tcph[0], tcph[1]
	return sport, dport

# Returns if the received protocol is TCP
def isTCP(proto):
	if proto == IP_TCP:
		TRANS_COUNT["TCP"] += 1
		return True
	return False

# Returns if the received protocol is UDP
def isUDP(proto):
	if proto == IP_UDP:
		TRANS_COUNT["UDP"] += 1
		return True
	return False

# Returns if the received protocol is ARP
def isARP(proto):
	if proto == ETH_ARP:
		return True
	return False

# Returns if the received protocol is IP
def isIP(proto):
	if proto == ETH_IP:
		return True
	return False

# Missing code here
# Add function to check ICMP over IP
# Returns if the received protocol is ICMP
def isICMP(proto):
	if proto == ICMP:
		TRANS_COUNT["ICMP"] += 1
		return True
	return False

# Returns if the received protocol is HTTP
def isHTTP(port):
	if port == App_DIC["HTTP"] or port == App_DIC["HTTPS"]:
		APP_COUNT["HTTP"] += 1
		return True
	return False

# Returns if the received protocol is SSH
def isSSH(port):
	if port == App_DIC["SSH"]:
		APP_COUNT["SSH"] += 1
		return True
	return False

# Returns if the received protocol is DNS
def isDNS(port):
	if port == App_DIC["DNS"]:
		APP_COUNT["DNS"] += 1
		return True
	return False

# Returns if the received protocol is SMTP
def isSMTP(port):
	if port == App_DIC["SMTP"]:
		APP_COUNT["SMTP"] += 1
		return True
	return False


# Missing code here.
# Create a socket (sock) to read AF_PACKET, in RAW mode, for layer protocol 3.
# Hint htons(0x0003)
try: 
	sock = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error , msg:
	print "Error: %s, Msg: %s".format(socket.error, msg)
	sock.close()

# Loop to read the packets from the kernel buffer.
while True:
	
	# Try and Except to catch the CTRL-C signal.  Python is super cool!
	try:

		# Read packet from the kernel buffer
		pkt = sock.recv(4096)
		PACKETS += 1

		# Extract the ethernet header.  Size is 14 bytes.
		ethHeader = pkt[:14]
	
		# Extract the source and destination mac addresses and the eth protocol
		smac, dmac, eth_proto = getEthernetFrame(ethHeader)
	
		# Nested if/else checks if protocol over ethernet is ARP or IP
		if isARP(eth_proto):
			# If ARP only print the ethernet SRC and DST MAC addresses
			print "ARP", "\nSMAC: ", smac, "\nDMAC: ", dmac,
			ETH_COUNT["ARP"] += 1


		elif isIP(eth_proto):
			# Print the ethernet SRC and DST MAC addresses
			print "\nIP", "\nSMAC: ", smac, "\nDMAC: ", dmac,

			# Missing code here
			# Extract the IP header.  IP Header is 20 bytes.
			ipHeader = pkt[14:34]
			sip, dip, ip_proto = getIPInfo(ipHeader)

			# Print IP information
			print "\nSrcIP:", sip, "\nDstIP:", dip, "\nProto:", ip_proto, "("+Proto_DIC[str(ip_proto)]+")"
			ETH_COUNT["IP"] += 1
	
			# If TCP or UDP extract the source and destination ports...
			if isTCP(ip_proto) or isUDP(ip_proto):
				tcHeader = pkt[34:54]
				sport, dport = getPorts(tcHeader)
				print "SrcP: ", sport, "\nDstP: ", dport

				# App layer protocol 
				if isHTTP(dport) or isHTTP(sport):
					print "HTTP"
					print getHTTPInfo(tcHeader)
				elif isSSH(dport) or isSSH(sport):
					print "SSH"
				elif isDNS(sport) or isDNS(sport):
					print "DNS"
				elif isSMTP(sport) or isSMTP(sport):
					print "SMTP"
				else:
					APP_COUNT["Others"] += 1


			elif isICMP(ip_proto):
				ICMPHEADER = pkt[34:38]
				TYPE, CODE, CHECKSUM = getICMPInfo(ICMPHEADER)
				print "ICMP:", TYPE, CODE, CHECKSUM
				print "Type:", TYPE, Mesg_DIC[str(TYPE)]

			else:
				TRANS_COUNT["Others"] += 1
				continue

		else:
			ETH_COUNT["Others"] += 1
			continue
		

	except KeyboardInterrupt:
		log = "Total Packets sniffed: " + str(PACKETS)
		log += "\nFrom the "+ str(PACKETS)+ " packets:"
		a = "\n\t"
		b = 0
		for i in ETH_COUNT: 
			b += ETH_COUNT[i]
			log += a + str(ETH_COUNT[i]) + " where " + i 
		log += "\nFrom the "+ str(b)+ " IP packets:"
		c = 0
		for i in TRANS_COUNT: 
			c += TRANS_COUNT[i]
			log += a + str(TRANS_COUNT[i]) + " where " + i
	 	log += "\nFrom the "+ str(c)+ " TCP and UDP packets:"
	 	for i in APP_COUNT:
			log += a + str(APP_COUNT[i]) + " where " + i

		# The code here is excecuted when the CTRL-C signal is received.
		try: 
			if (sys.argv[1] in 'yYes'):
				with open('log.txt', 'w+') as file:
					file.write(log)
		except:
			pass
		finally:
			print "\n", log
			print "\n\nSniffed "+ str(PACKETS) + " packets before you or something interrupted me!"
			print "BYE! :)"
			sys.exit()

	except:
		with open('errors.txt', 'a') as file:
			file.write('\n\n')
			traceback.print_exc(1,file)
		continue