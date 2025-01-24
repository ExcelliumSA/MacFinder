from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.eap import EAP
from scapy.layers.dhcp import DHCP, BOOTP, IP, UDP
import time
from threading import Thread, Lock

# Tool to simulate a MAC whitelisting with EAP CISCO like seen in real life one time only :)

# Just run the tool on a dummy interface, or a real.
# That tool send a DHCP offer only after

# create a dummy interface : 
## sudo ip link add eaptest type dummy
## sudo ifup eaptest
## sudo service networking restart

# change the interface on the following line and run it without args

# Parameters
interface = "eaptest"
dhcp_request_ids = []
mac_activity = {}
mac_lock = Lock()

def send_dhcp_offer(mac, xid):
    print(f"Preparing DHCP Offer for MAC: {mac}, XID: {xid}")
    offer = (
        Ether(dst=mac) /
        IP(src="13.37.17.37", dst="255.255.255.255") /
        UDP(sport=67, dport=68) /
        BOOTP(op=2, yiaddr="13.37.17.37", chaddr=mac, xid=xid) /
        DHCP(options=[("message-type", "offer"), ("server_id", "13.37.17.37"), ("lease_time", 86400), "end"])
    )
    sendp(offer, iface=interface, verbose=False)
    print(f"========== DHCP Offer sent to MAC: {mac} ==========")

def send_eap_sequence(mac):
    global mac_activity
    print(f"Starting EAP sequence for MAC: {mac}")
    eap_identity = Ether(dst=mac) / LLC() / SNAP() / EAPOL(version=1, type=0) / EAP(code=1, id=1, type=1)
    eap_failure = Ether(dst=mac) / LLC() / SNAP() / EAPOL(version=1, type=0) / EAP(code=4, id=1, type=1)  # EAP Failure

    # Send 3 request identity with 7s between each
    for i in range(3):
        print(f"Sending EAP Request Identity {i+1}/3 to MAC: {mac}")
        sendp(eap_identity, iface=interface, verbose=False)
        time.sleep(7)

    # Send EAP failure
    print(f"Sending EAP Failure to MAC: {mac}")
    sendp(eap_failure, iface=interface, verbose=False)


    with mac_lock:
        mac_activity[mac]['sequence_count'] += 1
        mac_activity[mac]['last_sequence'] = time.time()
    print(f"EAP sequence completed for MAC: {mac}")

# DHCP monitoring
def monitor_dhcp():
    def handle_dhcp(packet):
        print("_______")
        if DHCP in packet and packet[DHCP].options[0][1] == 1:  # DHCP Discover
            mac = packet[Ether].src
            request_id = packet[BOOTP].xid

            print(f"DHCP Request detected with ID: {request_id} from MAC: {mac}")

            with mac_lock:
                current_time = time.time()
                if mac not in mac_activity:
                    mac_activity[mac] = {'last_sequence': 0, 'sequence_count': 0}

                if mac:
                    print(mac.startswith("44:73:d6"))
                if mac_activity[mac]['sequence_count'] > 2:
                    mac_activity[mac]['sequence_count'] = 0
                if mac_activity[mac]['sequence_count'] == 2:
                    print(f" ++++ Sending DHCP Offer to MAC: {mac} ++++")
                    send_dhcp_offer(mac, request_id)
                elif current_time - mac_activity[mac]['last_sequence'] > 60:
                    print(f"Starting new EAP sequence for MAC: {mac}")
                    Thread(target=send_eap_sequence, args=(mac,)).start()

    print("Starting DHCP sniffing...")
    sniff(filter="port 68", iface=interface, prn=handle_dhcp, store=0)

if __name__ == "__main__":
    print(f"Listening for DHCP requests on {interface}...")
    monitor_dhcp()
