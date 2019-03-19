import socket
import struct

def parsing_ethernet_header(data):
    ethernet_header = struct.unpack("!6c6c2s", data)
    ether_src = convert_address(ethernet_header[0:6])
    ehter_dest = convert_address(ethernet_header[6:12])
    ip_header = "0x"+ethernet_header[12].hex()

    print("====== ethernet header ======")
    print("src_mac_address: ", ether_src)
    print("dest_mac_address: ", ehter_dest)
    print("ip_version", ip_header)

def convert_address(data):
    addr = list()
    for i in data:
        addr.append(i.hex())
    addr = ":".join(addr)
    return addr


def parsing_ip_header(data):
    ip_header = struct.unpack("!1c1c2s2s2s1c1c2s4c4c", data)
    ip_version = int(ip_header[0].hex(),16) >> 4
    ip_length = int(ip_header[0].hex(),16) & 0x0f
    ip_dif_ser_code = int(ip_header[1].hex(),16) >> 2
    ip_exp_con_noti = int(ip_header[1].hex(), 16) & 0x03
    ip_total_length = int(ip_header[2].hex(), 16)
    ip_identification = int(ip_header[3].hex(), 16)
    ip_flags = "0x"+ip_header[4].hex()
    ip_res_bit = int(ip_header[4].hex(),16) >> 15
    ip_not_frag = (int(ip_header[4].hex(),16) & 0x4fff) >> 14
    ip_fragments = (int(ip_header[4].hex(),16) & 0x2fff) >> 13
    ip_fragments_off = int(ip_header[4].hex(),16) & 0x1fff
    ip_Time_to_live = int(ip_header[5].hex(), 16)
    ip_protocol = int(ip_header[6].hex(),16)
    ip_head_check = "0x"+ip_header[7].hex() 
    ip_src_address = convert_ip_address(ip_header[8:12])
    ip_dst_address = convert_ip_address(ip_header[12:16])
    
    print("====== ip address ======")
    print("ip_version : ", ip_version)
    print("ip_Length : ", ip_length)
    print("differentiated_service_codepoint : ", ip_dif_ser_code)
    print("explicit_congestion_notification : ", ip_exp_con_noti)
    print("total_length : ", ip_total_length)
    print("identification : ", ip_identification)
    print("flags : ", ip_flags)
    print(">>>reserved_bit : ", ip_res_bit)
    print(">>>not_fragment : ", ip_not_frag)
    print(">>>fragments : ", ip_fragments)
    print(">>>fragments_offset : ", ip_fragments_off)
    print("Time to live : ", ip_Time_to_live)
    print("protocol : ", ip_protocol)
    print("header checksum : ",ip_head_check)
    print("source_ip_address : ", ip_src_address)
    print("dest_ip_address : ", ip_dst_address)
    
    return ip_protocol

def convert_ip_address(data):
    ip_addr = list()
    for i in data:
        ip_addr.append(str(int(i.hex(),16)))
    ip_addr = ".".join(ip_addr)
    return ip_addr

def parsing_tcp_header(data):
    tcp_header = struct.unpack("!2s2s4s4s1c1c2s2s2s", data)
    tcp_src_port = int(tcp_header[0].hex(),16)
    tcp_dec_port = int(tcp_header[1].hex(), 16)
    tcp_seq_num = int(tcp_header[2].hex(), 16)
    tcp_ack_num = int(tcp_header[3].hex(), 16)
    tcp_header_len = int(tcp_header[4].hex(), 16) >> 4
    tcp_flags = (int(tcp_header[4].hex(), 16) & 0x0f)+int(tcp_header[5].hex(), 16) 
    tcp_reserved = (int(tcp_header[4].hex(), 16) & 0x0f) >>1
    tcp_nonce = int(tcp_header[4].hex(),16) & 0x01
    tcp_cwr = int(tcp_header[5].hex(),16) >> 7
    tcp_ecn = (int(tcp_header[5].hex(),16) & 0x40) >> 6
    tcp_urgent = (int(tcp_header[5].hex(), 16) & 0x20) >> 5
    tcp_ack = (int(tcp_header[5].hex(), 16) & 0x10) >> 4
    tcp_push = (int(tcp_header[5].hex(), 16) & 0x08) >> 3
    tcp_reset = (int(tcp_header[5].hex(), 16) & 0x04) >> 2
    tcp_syn = (int(tcp_header[5].hex(), 16) & 0x02) >> 1
    tcp_fin = (int(tcp_header[5].hex(),16) & 0x01)
    tcp_window = int(tcp_header[6].hex(), 16)
    tcp_checksum = "0x"+tcp_header[7].hex()
    tcp_urgent = int(tcp_header[8].hex(), 16)

    print("====== tcp address ======")
    print("src_port : ", tcp_src_port)
    print("dec_port : ", tcp_dec_port)
    print("seq_num : ", tcp_seq_num)
    print("ack_num : ", tcp_ack_num)
    print("header_len : ", tcp_header_len)
    print("flags : ", tcp_flags)
    print(">>>reserved : ", tcp_reserved)
    print(">>>nonce : ", tcp_nonce)
    print(">>>cwr : ", tcp_cwr)
    print(">>>ecn : ", tcp_ecn)
    print(">>>urgent : ", tcp_urgent)
    print(">>>ack : ", tcp_ack)
    print(">>>push : ", tcp_push)
    print(">>>reset : ", tcp_reset)
    print(">>>syn : ", tcp_syn)
    print(">>>fin : ", tcp_fin)
    print("window_size_value : ", tcp_window)
    print("checksum : ", tcp_checksum)
    print("urgent_pointer : ", tcp_urgent)

def parsing_udp_header(data):
    udp_header = struct.unpack("!2s2s2s2s", data)
    udp_src_port = int(udp_header[0].hex(), 16)
    udp_dst_port = int(udp_header[1].hex(), 16)
    udp_leng = int(udp_header[2].hex(), 16)
    udp_checksum = "0x"+udp_header[3].hex()
    
    print("====== udp header ======")
    print("src_port : ", udp_src_port)
    print("dst_port : ", udp_dst_port)
    print("leng : ", udp_leng)
    print("header checksum : 0x", udp_checksum)

recv_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x800))

while True:
    data = recv_socket.recvfrom(65535)
    parsing_ethernet_header(data[0][0:14])
    protocol = parsing_ip_header(data[0][14:34])
    if protocol == 6:
        parsing_tcp_header(data[0][34:54])
    elif protocol == 17:
        parsing_udp_header(data[0][34:42])
