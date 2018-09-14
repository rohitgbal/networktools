import socket
import struct
import textwrap
import binascii

TAB1 = '\t -'
TAB2 = '\t\t -'
TAB3 = '\t\t\t -'
TAB4 = '\t\t\t\t -'

DTAB1 = '\t'
DTAB2 = '\t\t'
DTAB3 = '\t\t\t'
DTAB4 = '\t\t\t\t'

#Main Program    
def main():
    con=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
    while True:
        rdata,addr=con.recvfrom(65535)
        dmac, smac, pcol, edata = eth_pack(rdata)
       # print("\n############ Ethernet Frame ############\n")
        #print('\n Source : {} \n Destination : {} \n Protocol : {}'.format(dmac,smac,pcol))

        #For  IPv4
        if pcol == 8:
        	ver,header_len, ttl, ptcl, sip, dip, idata = ip_pack(edata)
        	#print(TAB1+'$$IPv4 Packet$$')
        	#print(TAB2+'Version {} Header Len {} TTL {}'.format(ver,header_len, ttl))
        	#print(TAB2+'Protocol {} Src IPv4 {} Dest IPv4 {}'.format(ptcl,sip, dip))
        	#print(TAB2+'DATA')
        	print(multi_line_format(DTAB2,"".join(map(chr, idata))))

        	# ICMP Packets 
        	if pcol == 1 :
        		icmp_type, code, checksum, data = icmp_pack(idata)
        	#	print(TAB1+'$$ICMP Packet$$')
        	#	print(TAB2+'ICMP {} Code {} Check Sum {}'.format(icmp_type, code, checksum))
        	#	print(TAB2+'DATA')
        	#	print(TAB2+multi_lin e_format(DTAB2,data))

        	# TCP Packets
        	elif pcol ==  6:
        		(s_port, d_port, seq, ack, u_flag,a_flag, p_flag, r_flag, s_flag, f_flag, data) = tcp_seg(idata)
        		print(TAB1+'$$TCP Packets$$')
        		print(TAB2+'Dest_Port {} Src Port {}'.format(d_port,s_port))
        		print(TAB2+'Seq No {} Ack No {}'.format(seq,ack))
        		print(TAB3+'Uflag {} Aflag {}, Pflag {} Rflag {} Sflag{} Fflag {}'.format(u_flag, a_flag, p_flag, r_flag, s_flag, f_flag))
        		print(TAB2+'DATA')
        		print(multi_line_format(DTAB2,data))
        	#UDP Packets
        	elif pcol == 17:
        		(s_port,d_port, size, data) = udp_seg(idata)


#unpack Ethernet frame
def eth_pack(data):
    d_mac,s_mac,pcol=struct.unpack('! 6s 6s H',data[:14])
    return get_mac(d_mac),get_mac(s_mac),socket.htons(pcol),data[14:]



#Formatting into Standard mac address format
def get_mac(baddr):
    saddr=map('{:02x}'.format,baddr)
    maddr=':'.join(saddr).upper()
    return maddr
    
#unpack IPv4 Packet
def ip_pack(data):
    ver_header_len=data[0]
    ver=ver_header_len>>4
    header_len=(ver_header_len & 15)*4
    ttl,ptcl,sip,dip = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return ver,header_len,ttl,ptcl,get_ip(sip), get_ip(dip), data[header_len:]

#Formatting into Standard IPv4 (Dotted Decimal) Format
def get_ip(ip):
    ipv4='.'.join(map(str,ip))
    return ipv4

#Unpack ICMP Segments
def icmp_pack(data):
    icmp_type,code,checksum = struct.unpack('! B B H',data[:4])
    return icmp_type, code, checksum, data[4:]
    
#unpack UDP Segments
def udp_seg(data):
	s_port,d_port, size = struct.unpack('! H H 2x H', data[:8])
	return s_port,d_port,size,data[8:]

#Unpack TCP Segments
def tcp_seg(data):
    (s_port, d_port, seq, ack, off_resv_flags ) = struct.unpack('! H H L L H', data[:14])
    offset = (off_resv_flags >> 12) * 4
    u_flag = (off_resv_flags & 32) >> 5
    a_flag = (off_resv_flags & 16) >> 4
    p_flag = (off_resv_flags & 8) >> 3
    r_flag = (off_resv_flags & 4) >> 3
    s_flag = (off_resv_flags & 2) >> 1
    f_flag = (off_resv_flags & 1)
    return s_port, d_port, seq, ack, u_flag,a_flag, p_flag, r_flag, s_flag, f_flag, data[offset:]

#Format data into Seperate lines
def multi_line_format(prefix, string ,size = 80):
	size -= len(prefix)
	if isinstance(string,bytes):
		string = ''.join(r'\x{:2x}'.format(byte) for byte in string)
		if size % 2:
			size -= 1
	return '\n'.join([prefix +line for line in textwrap.wrap(string,size)])

main()
