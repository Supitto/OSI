#!/usr/bin/python3

import struct
import pacote
import sock
import asyncio
import socket
import eth
import ip

class Despachador:


  def __init__(self):
    self.meias = {}

    self.fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(eth.ETH_P_ALL))
    self.fd.bind((eth.if_name, 0))
    self.ip_handler = ip.IP()
    self.loop = asyncio.get_event_loop()
    self.loop.add_reader(self.fd, self.recebe_binario, self.fd)

  def recebe_binario(self, fd):
    #Trata o etherframe
    frame = fd.recv(1518000)

    dst_mac, src_mac, ethertype, datagrama = eth.desmonta_quadro(frame)
    if not dst_mac == eth.src_mac: return
    if not ethertype == eth.ETH_P_IP: return 

    raw_pac = self.ip_handler.digere_datagrama(datagrama)
    if raw_pac == None:
      return

    try:
      pac = pacote.traduz_pacote(raw_pac)
    except AssertionError as e:
      print('fail')
      return
    
    print(pac.porta_destino,self.meias.keys())
    if not pac.porta_destino in self.meias.keys():
      return
    print("processando")
    self.meias[pac.porta_destino].recebe_pacote(pac)

  def envia_binario(binario):
    datagrama = self.ip.monta_ip(binario)
    quadro = self.eth.monta_quadro(datagrama)
    self.fd.send(quadro)

  def registra_servico(self, porta):
    self.meias[porta] = sock.Sock(self.fd,porta)
