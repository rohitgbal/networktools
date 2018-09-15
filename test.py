import socket
import struct,sys

#Main Program    
def main():
	con=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.ntohs(3))
	while True:
		rdata,addr=con.recvfrom(65535)
		dmac, smac, pcol, edata = eth_pack(rdata)
		if pcol == 8:
			ver,header_len, ttl, ptcl, sip, dip, idata = ip_pack(edata)
			if ptcl ==  6:
				(s_port, d_port, seq, ack, u_flag,a_flag, p_flag, r_flag, s_flag, f_flag, data) = tcp_seg(idata)
				if d_port == 22:
					print ('Size : {}'.format(sys.getsizeof(data)))

#unpack Ethernet frame
def eth_pack (data) :
	d_mac,s_mac,pcol=struct.unpack('! 6s 6s H',data[:14])
	return d_mac,s_mac,socket.htons(pcol),data[14:]
    
#unpack IPv4 Packet
def ip_pack(data):
    ver_header_len=data[0]
    ver=ver_header_len>>4
    header_len=(ver_header_len & 15)*4
    ttl,ptcl,sip,dip = struct.unpack('! 8x B B 2x 4s 4s',data[:20])
    return ver,header_len,ttl,ptcl,sip,dip, data[header_len:]

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

main()
