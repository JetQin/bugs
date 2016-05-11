# /usr/bin/python arp_lie.py

import os
import fcntl
import struct
import uuid
import socket
import optparse
from scapy.all import srp,Ether,ARP,conf,sendp

def get_mac_address(): 
    mac=uuid.UUID(int = uuid.getnode()).hex[-12:] 
    return ":".join([mac[e:e+2] for e in range(0,11,2)])

def get_local_ip():
    # print "host_name:"+socket.gethostname()
    host_name = socket.getfqdn(socket.gethostname())
    local_address = socket.gethostbyname(host_name) 
    return local_address
     
def arping(iprange="192.168.1.0/24"):
          conf.verb=0
          ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=iprange),
                              timeout=2)
          collection = []
          for snd, rcv in ans:
            result = rcv.sprintf(r"%ARP.psrc% %Ether.src%").split()
            collection.append(result)
          return collection

def arp_cheating(gateway,values):
    victims = []
    gateways = []
    for ip, mac in values:
       local_mac = get_mac_address()
       victim = Ether(src=local_mac,dst=mac)/ARP(op=0x0002, hwsrc=local_mac,psrc=gateway,pdst=ip,hwdst=mac)
       gateway = Ether(src=local_mac,dst=mac)/ARP(op=0x0002, hwsrc=local_mac,psrc=gateway,pdst=ip,hwdst=mac)
       print ip, mac
 
  
def main():
    """Runs program and handles command line to execute arp cheating"""
    p = optparse.OptionParser(description=' Finds MAC Address of IP address(es)',
                                  prog='arp_lie',
                                  version='arp_lie 0.1',
                                  usage='%arp_lie [192.168.1.1 or 192.168.1.0/24]')
    
    
    print "local mac:"+get_mac_address()
    print "local address:"+get_local_ip()
       
    options, arguments = p.parse_args()
    if len(arguments) == 1:
      values = arping(iprange=arguments)
      for ip, mac in values:
        print ip, mac
    else:
      p.print_help()
      
if __name__ == '__main__':
  main()

