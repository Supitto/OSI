#!/usr/bin/python3
#iptables -I OUTPUT -p tcp --tcp-flags RST RST -j DROP
#

import subprocess
import despachador

if __name__ == "__main__":

  subprocess.run(["iptables","-I","OUTPUT","-p","tcp","--tcp-flags","RST","RST","-j","DROP"])

  cleyton = despachador.Despachador()
  cleyton.registra_servico(8000)
  cleyton.loop.run_forever()
