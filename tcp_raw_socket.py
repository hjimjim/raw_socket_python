import socket, sys
from struct import *

#checksum functions needed for calculation checksum
def checksum(msg):
	s = 0
	
	# loop taking 2 characters at a time
	for i in range(0, len(msg), 2):
		w =1 #ord(msg[i]) + (ord(msg[i+1]) << 8 )
		s = s + w
	
	s = (s >> 16) + (s & 0xffff)
	s = s + (s >> 16)
	
	#complement and mask to 4 byte short
	s = ~s & 0xffff
	
	return s


def create_ip_header(source_ip, dest_ip):
	ip_ihl = 5		# Internet Header Length. Default is 5 (20 bytes).
	ip_ver = 4		# IP version. default is 4
	ip_tos = 0
	ip_tot_len = 0	# kernel will fill the correct total length
	ip_id = 54321	# Id of this packet
	ip_frag_off = 0 # Fragment offset if any. default 0
	ip_ttl = 255	# Time To Live for the packet. default 255
	ip_proto = socket.IPPROTO_TCP # Protocol for contained packet. default is TCP.
	ip_check = 0	# kernel will fill the correct checksum
	ip_saddr = socket.inet_aton(source_ip)
	ip_daddr = socket.inet_aton(dest_ip)
	ip_ihl_ver = (ip_ver << 4) + ip_ihl

	# the ! in the pack format string means network order
	ip_header = pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, 
						ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)

	return ip_header

def create_tcp_header(source_ip, dest_ip,user_data):
	tcp_source = 1234	# source port
	tcp_dest = 80	# destination port
	tcp_seq = 454 	# tcp sequence number: set a random number for first package and the ack number of previous received ack package otherwise.
	tcp_ack_seq = 0 # TCP ack number: previous received seq + number of bytes received
	tcp_doff = 5	# data offset, default 0 / 4 bit field, size of tcp header, 5 * 4 = 20 bytes
	#tcp flags 		# TCP flags in an array with the structure [HS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
	tcp_fin = 0
	tcp_syn = 1
	tcp_rst = 0
	tcp_psh = 0
	tcp_ack = 0
	tcp_urg = 0
	
	tcp_window = socket.htons (5840)	# maximum allowed window size
	tcp_check = 0
	tcp_urg_ptr = 0  # Urgent pointer if URG flag is set

	tcp_offset_res = (tcp_doff << 4) + 0
	tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)

	# the ! in the pack format string means network order
	first_tcp_header = pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

	# pseudo header fields
	source_address = socket.inet_aton(source_ip)
	dest_address = socket.inet_aton(dest_ip)
	placeholder = 0
	protocol = socket.IPPROTO_TCP
	tcp_length = len(first_tcp_header) + len(user_data)

	psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)
	psh = psh + first_tcp_header + user_data.encode("ascii")
	tcp_check = checksum(psh)

	# make the tcp header again and fill the correct checksum - remember checksum is NOT in network byte order
	tcp_header = pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + pack('H' , tcp_check) + pack('!H' , tcp_urg_ptr)

	return tcp_header


def create_packet():
	#create a raw socket
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
	except socket.error as msg:
		print('Socket could not be created. Error Code : ' + str(msg))
		sys.exit()

	source_ip = '10.0.2.15'  # fill this with src ip
	dest_ip = '8.8.8.8'	# dst ip or socket.gethostbyname('www.google.com')
	user_data = 'Hello, how are you'

	ip_header = create_ip_header(source_ip, dest_ip)
	# final full packet - syn packets dont have any data
	packet = ''
	tcp_header = create_tcp_header(source_ip, dest_ip, user_data)
	packet = ip_header + tcp_header + user_data.encode('ascii')

	#Send the packet  
	loop = 0
	while loop < 100:
		print("num : " + str(loop))
		s.sendto(packet, (dest_ip , 0 ))	# put this in a loop if you want to flood the target
		loop = loop + 1

print("start sending packet")
create_packet()
