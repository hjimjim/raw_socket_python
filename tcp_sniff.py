#Packet sniffer in python
#For Linux - Sniffs all incoming and outgoing packets :)

import socket, sys
from struct import *

#Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" %( a[0] , a[1] , a[2], a[3], a[4] , a[5])
  #b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(str(a[0])) , ord(str(a[1])) , ord(str(a[2])), ord(str(a[3])), ord(str(a[4])) , ord(str(a[5])))
  return b

def getflags(packet):
    Flag_URG = {0:"", 1: "URG-Urgent flag)"}
    Flag_ACK = {0:"",1: "ACK-Acknowledgment flag"}
    Flag_PSH = {0:"",1: "PSH-Push flag"}
    Flag_RST = {0:"",1: "RST-Reset flag"}
    Flag_SYN = {0:"",1: "SYN-Synchronize flag"}
    Flag_FIN = {0:"",1: "FIN-End of data flag"}

    URG = packet & 0x020
    URG >>= 5
    ACK = packet & 0x010
    ACK >>= 4
    PSH = packet & 0x008
    PSH >>= 3
    RST = packet & 0x004
    RST >>= 2
    SYN = packet & 0x002
    SYN >>= 1
    FIN = packet & 0x001
    FIN >>= 0


    new_line = "\n"

    Flags = Flag_URG[URG] + new_line + Flag_ACK[ACK] + new_line + Flag_PSH[PSH] + new_line + Flag_RST[RST] + new_line + Flag_SYN[SYN] + new_line + Flag_FIN[FIN]
    return Flags


#create a AF_PACKET type raw socket (thats basically packet level)
#define ETH_P_ALL    0x0003          /* Every packet (be careful!!!) */
try:
	s = socket.socket(socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error as msg:
	print ('Socket could not be created. Error Code : ' + str(msg) + ' Message ' + msg)
	sys.exit()

# receive a packet
while True:
	packet = s.recvfrom(65565)
	
	#packet string from tuple
	packet = packet[0]
	
	#parse ethernet header
	eth_length = 14
	
	eth_header = packet[:eth_length]
	eth = unpack('!6s6sH' , eth_header)
	eth_protocol = socket.ntohs(eth[2])
	print ('Destination MAC : ' + eth_addr(packet[0:6]) + ' Source MAC : ' + eth_addr(packet[6:12]) + ' Protocol : ' + str(eth_protocol))

	#Parse IP packets, IP Protocol number = 8
	if eth_protocol == 8 :
		#Parse IP header
		#take first 20 characters for the ip header
		ip_header = packet[eth_length:20+eth_length]
		
		#now unpack them :)
		iph = unpack('!BBHHHBBH4s4s' , ip_header)

		version_ihl = iph[0]
		version = version_ihl >> 4
		ihl = version_ihl & 0xF

		iph_length = ihl * 4

		ttl = iph[5]
		protocol = iph[6]
		s_addr = socket.inet_ntoa(iph[8])
		d_addr = socket.inet_ntoa(iph[9])

		print ('Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr))

		#TCP protocol
		if protocol == 6 :
			t = iph_length + eth_length
			tcp_header = packet[t:t+20]

			#now unpack them :)
			tcph = unpack('!HHLLBBHHH' , tcp_header)
			
			source_port = tcph[0]
			dest_port = tcph[1]
			sequence = tcph[2]
			acknowledgement = tcph[3]
			doff_reserved = tcph[4]
			tcph_length = doff_reserved >> 4
			
			print(getflags(tcph[3]))	
			print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length))
			h_size = eth_length + iph_length + tcph_length * 4
			data_size = len(packet) - h_size
			
			#get data from the packet
			#data = packet[h_size:]
			#print ("Data : " + data.decode("utf-8","strict"))
		#some other IP packet like ICMP/UDP/IGMP
		else :
			print ('Protocol other than TCP')

		"""
		#ICMP Packets
		elif protocol == 1 :
			u = iph_length + eth_length
			icmph_length = 4
			icmp_header = packet[u:u+4]

			#now unpack them :)
			icmph = unpack('!BBH' , icmp_header)
			
			icmp_type = icmph[0]
			code = icmph[1]
			checksum = icmph[2]
			
			print ('Type : ' + str(icmp_type) + ' Code : ' + str(code) + ' Checksum : ' + str(checksum))
			
			h_size = eth_length + iph_length + icmph_length
			data_size = len(packet) - h_size
			
			#get data from the packet
			data = packet[h_size:]
		#	print ("Data : " + data.decode("utf-8"))
		
			#UDP packets
			elif protocol == 17 :
			u = iph_length + eth_length
			udph_length = 8
			udp_header = packet[u:u+8]

			#now unpack them :)
			udph = unpack('!HHHH' , udp_header)
			
			source_port = udph[0]
			dest_port = udph[1]
			length = udph[2]
			checksum = udph[3]
			
			print ('Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Length : ' + str(length) + ' Checksum : ' + str(checksum))
			
			h_size = eth_length + iph_length + udph_length
			data_size = len(packet) - h_size
			
			#get data from the packet
			data = packet[h_size:]
			
			print ("Data : " + data.decode("utf-8"))
		"""