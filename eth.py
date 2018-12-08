import struct

ETH_P_ALL = 0x0003
ETH_P_IP  = 0x0800

ICMP = 0x01  # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers

# Coloque aqui o endereço de destino para onde você quer mandar o ping
dest_ip = '1.1.1.1'

# Coloque abaixo o endereço IP do seu computador na sua rede local
src_ip = '200.136.192.167'

# Coloque aqui o nome da sua placa de rede
if_name = 'wlp3s0'

# Coloque aqui o endereço MAC do roteador da sua rede local (arp -a | grep _gateway)
dest_mac = '44:31:92:b8:fa:99'

# Coloque aqui o endereço MAC da sua placa de rede (ip link show dev wlan0)
src_mac = '5c:c9:d3:8c:2e:b7'

def desmonta_quadro(bin):
    mac_dst = ''.join([hex(a)[2:]+':' for a in bin[:6]])[:-1]
    mac_src = ''.join([hex(a)[2:]+':' for a in bin[6:12]])[:-1]
    ethertype = struct.unpack('!H',bin[12:14])[0]
    payload = bin[14:]
    print(mac_dst, mac_src)

    return mac_dst, mac_src, ethertype, payload

def monta_quadro(datagram):
    eth_header = mac_addr_to_bytes(dest_mac) + \
        mac_addr_to_bytes(src_mac) + \
        struct.pack('!H', 0x0800)
    return eth_header + datagram
