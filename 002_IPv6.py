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
        #print("\n############ Ethernet Frame ############\n")
        #print('\n Source : {} \n Destination : {} \n Protocol : {}'.format(dmac,smac,pcol))
        if pcol == 56710:
        	ver,t_class,f_ctrl = ip_pack(edata);
        	print('\n Version: {} \n Trafiic Class{} \n Flow Control {}'.format(ver,t_class,f_ctrl))

#unpack Ethernet frame
def eth_pack(data):
    d_mac,s_mac,pcol=struct.unpack('! 6s 6s H',data[:14])
    return get_mac(d_mac),get_mac(s_mac),socket.htons(pcol),data[14:]

#Formatting into Standard mac address format
def get_mac(baddr):
    saddr=map('{:02x}'.format,baddr)
    maddr=':'.join(saddr).upper()
    return maddr

#unpack IPv6 Packet
def ip_pack(data):
    ver_header_len = data[0]
    ver=ver_header_len>>4
    temp_t_class = data[1]
    t_class = (temp_t_class >> 4) & 255
    temp_f_ctrl = data[3]
    f_ctrl = temp_f_ctrl & 4294963200
    return ver,t_class,f_ctrl
    
main()
