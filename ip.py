#!/usr/bin/python3

import socket
import asyncio
import struct
import threading


class IP:

    def __init__(self):
        self.conexoes = {}

    def delete(self, num):
        if num in self.conexoes.keys():
            del self.conexoes[num]

    def separa_cabecalho_payload(self, binario):
        if not int(binario[0]>>4) == 4:
            return None, None
        ihl = binario[0] & 0x0f
        return binario[:ihl*4], binario[ihl*4:]

    def calc_checksum(self, segment):
        if len(segment) % 2 == 1:
            # se for ímpar, faz padding à direita
            segment += b'\x00'
        checksum = 0
        for i in range(0, len(segment), 2):
            x, = struct.unpack('!H', segment[i:i+2])
            checksum += x
            while checksum > 0xffff:
                checksum = (checksum & 0xffff) + 1
        checksum = ~checksum
        return checksum & 0xffff


    def desmonta_cabecalho(self, cabecalho):
        versao_ihl, \
        dscp_ecn, \
        total_lenght, \
        identification, \
        flags_fragment, \
        time_to_live, \
        protocol,  \
        checksum, \
        source, \
        destination = struct.unpack('!BBHHHBBHII', cabecalho[:20])
        return versao_ihl, dscp_ecn, total_lenght, identification, flags_fragment, time_to_live, \
        protocol, checksum, source, destination

	#essa função é chupada do codigo do paulo
    def monta_ip(msg):
        global ip_pkt_id
        ip_header = bytearray(struct.pack('!BBHHHBBH',
                                0x45, 0,
                                20 + len(msg),
                                ip_pkt_id,
                                0,
                                15,
                                0x06,
                                0) +
                              ip_addr_to_bytes(src_ip) +
                          ip_addr_to_bytes(dest_ip))
        ip_header[10:12] = struct.pack('!H', calc_checksum(ip_header))
        ip_pkt_id += 1
        return ip_header + msg

    def digere_datagrama(self, datagrama, pseudo = True):
        cabecalho, payload = self.separa_cabecalho_payload(datagrama)
        if cabecalho == None:
            pass

        #print(payload)
        versao_ihl, dscp_ecn, total_lenght, identification, flags_fragment, time_to_live, \
        protocol, checksum, source, destination = self.desmonta_cabecalho(cabecalho)

        versao = versao_ihl >> 4

        fragment = flags_fragment & 0x1fff
        flags = flags_fragment >> 13

        tripla = (source, destination, identification)

        if not tripla in self.conexoes.keys():
            self.conexoes[tripla] = [set(), b"", None, 0, threading.Timer(60, self.delete, [tripla])]
            #start timer    
            self.conexoes[tripla][4].start()

        if fragment in self.conexoes[tripla][0]:
            pass

        self.conexoes[tripla][0].add(fragment)
        self.conexoes[tripla][3] += len(payload)    

        if len(self.conexoes[tripla][1]) > fragment:
            self.conexoes[tripla][1] += b'\xff' * (fragment-len(self.conexoes[tripla][0])) + payload
        else:
            self.conexoes[tripla][1] = self.conexoes[tripla][1][:fragment] + payload + self.conexoes[tripla][1][:fragment+len(payload)]

        if flags & 1 == 0:
            self.conexoes[tripla][2] = fragment+len(payload)
        
        if self.conexoes[tripla][3] == self.conexoes[tripla][2]:
            raw_pac = self.conexoes[tripla][1]
            # para o timer
            self.conexoes[tripla][4].cancel()
            del self.conexoes[tripla]
            if not pseudo:
                return raw_pac

            
            #print(versao_ihl >> 4, versao_ihl & 0x0f, total_lenght, identification, flags_fragment, time_to_live, \
            #    protocol, checksum, ''.join([str(int(hex(source)[2:][x*2:(x+1)*2],16))+'.' for x in range(4)])[:-1], \
            #    ''.join([str(int(hex(destination)[2:][x*2:(x+1)*2],16))+'.' for x in range(4)])[:-1])
            pseudo_header = struct.pack("!IIBBH",source,destination,0,protocol,len(raw_pac))
            return pseudo_header + raw_pac
            
        return None
