import argparse
import requests
import os
import random
import time
from datetime import datetime, timedelta
from scapy.all import Ether, IP, UDP, BOOTP, DHCP, srp, conf, Raw, sniff
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from colorama import init, Fore, Style
from threading import Lock
from scapy.all import *

# Initialize colorama
init(autoreset=True)

# Argument Parsing
parser = argparse.ArgumentParser(description="🚀 Optimized MAC OUI finder to bypass NAC 🔍")
parser.add_argument("--output", help="💾 Output file", type=str, default="valid_macs.txt")
parser.add_argument("--iface", help="🌐 Network interface for DHCP requests", type=str, default="eth0")
parser.add_argument("--timeout", help="⏱  DHCP response timeout (in seconds)", type=int, default=2)
parser.add_argument("--threads", help="⚙️  Number of threads for parallel testing", type=int, default=10)
parser.add_argument("--oui-file", help="📄 Path to local OUI file", type=str, default="/var/lib/ieee-data/oui.txt")
parser.add_argument("--filter", help="🔎 Keywords to filter OUI file (comma-separated, e.g., Cisco,HP)", type=str, default="")
parser.add_argument("--debug", help="🐞 Debug mode", action="store_true")
parser.add_argument("--update-oui", help="🔄 Force OUI list update", action="store_true")
parser.add_argument("--max-retries", help="🔄 Maximum number of retries for DHCP requests", type=int, default=3)  # Max retries argument
parser.add_argument("--eap", help="🎧 Listen for EAP and retry DHCP Discover on EAP failure", action="store_true")
parser.add_argument("--eap-session-repeat", help="Number of failure before giving up", action="store_true", default=2)
parser.add_argument("--eap-session-duration", help="Time between two EAP session (between the last FAILURE and the next REQUEST)", action="store_true", default=70)
parser.add_argument("--eap-debug", help="Print EAP information at the end", action="store_true", default=False)
args = parser.parse_args()

conf.checkIPaddr = False

# Mutex for thread-safe operations
lock = Lock()
lock_file = Lock()

eap_tested_mac = dict()
lock_eap = Lock()
tested_macs = set()

oui_list = []
vendors = {}

nb_wait_eap_cycle = 0
lock_nb_wait_eap_cycle = Lock()

pbar = None


def still_eap_cycle():
    if args.eap_debug:
        print(eap_tested_mac)
    return len(eap_tested_mac) != 0 or nb_wait_eap_cycle != 0

def sleep_between_eap(mac_dst):
    global nb_wait_eap_cycle
    with lock_nb_wait_eap_cycle:
        nb_wait_eap_cycle += 1
    time.sleep(args.eap_session_duration)
    test_mac(mac_dst[0:8], mac_dst, args.output, tested_macs, args.timeout, args.iface, args.debug, vendors, args.max_retries, force_retry=True)
    with lock_nb_wait_eap_cycle:
        nb_wait_eap_cycle -= 1


def parse_eap(packet):
    tmp = random.randint(0, 100000) 
    mac_dst = packet.getlayer('Ether').dst
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] NAC detected for : {mac_dst}")
    eap_code = packet.getlayer('EAP').code

    if eap_code == scapy.layers.eap.EAP.REQUEST:
        with lock_eap:
            if mac_dst not in eap_tested_mac:
                eap_tested_mac[mac_dst] = {'REQUEST': 0, 'FAILURE': 0}
            eap_tested_mac[mac_dst]['REQUEST'] += 1
    if eap_code == scapy.layers.eap.EAP.FAILURE:
        with lock_eap:
            eap_tested_mac[mac_dst]['FAILURE'] += 1
        if eap_tested_mac[mac_dst]['FAILURE'] < args.eap_session_repeat:
            # Run in thread for avoiding blocking AsyncSniff
            t = None
            t = Thread(target=sleep_between_eap, args=(mac_dst,))
            t.start()
            
        if eap_tested_mac[mac_dst]['FAILURE'] == args.eap_session_repeat:
            test_mac(mac_dst[0:8], mac_dst, args.output, tested_macs, args.timeout, args.iface, args.debug, vendors, args.max_retries, force_retry=True)
            del(eap_tested_mac[mac_dst])

def listen_for_eap(iface):
    """
    Listen for EAP packets targeting the specified MAC address within the given timeout.
    """
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Listening for EAP responses")
    try:
        t1 = AsyncSniffer(iface=iface, filter="ether proto 0x8870", prn=parse_eap)
        t1.start()
    except Exception as e:
        if args.debug:
            print(f"{Fore.RED}❗ [ERROR] Error while listening for EAP: {e}")
    return False



def parse_dhcp(packet):
    mac_dst = packet.getlayer('Ether').dst
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] DHCP offer received for {mac_dst}")
    if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
        ip_address = packet[BOOTP].yiaddr
        vendor = vendors.get(mac_dst[0:8], "Unknown Vendor")
        print(f"{Fore.GREEN}🎯 [FOUND] {mac_dst} | Vendor: {vendor} | DHCP Offer: {ip_address}")
        with lock_file, open(args.output, 'a') as file:
            file.write(f"{mac_dst} | Vendor: {vendor} | DHCP Offer: {ip_address}\n")
    
def listen_for_dhcp_offers(iface):
    """
    Listen for DHCP offers.
    """
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Listening for DHCP offers")
    try:
        t2 = AsyncSniffer(iface=iface, filter="udp src port 67 and udp dst port 68 and udp[250:1] = 2", prn=parse_dhcp)
        t2.start()
    except Exception as e:
        if args.debug:
            print(f"{Fore.RED}❗ [ERROR] Error while listening for DHCP: {e}")
    return False



# Function to fetch and update the OUI file if necessary
def update_oui_file(url, local_file):
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Fetching OUI list from {url}...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        if args.debug:
            print(f"{Fore.CYAN}🐞 [DEBUG] Writing fetched OUI data to {local_file}...")
        with open(local_file, 'w') as file:
            file.write(response.text)
        print(f"{Fore.GREEN}✅ [SUCCESS] OUI database updated successfully. 🌟")
    except requests.RequestException as e:
        print(f"{Fore.RED}❌ [ERROR] Failed to fetch OUI list: {e}")

# Function to check if the OUI file is outdated
def is_oui_file_outdated(local_file, days=7):
    if not os.path.exists(local_file):
        if args.debug:
            print(f"{Fore.CYAN}🐞 [DEBUG] OUI file {local_file} does not exist.")
        return True
    file_mod_time = os.path.getmtime(local_file)
    file_mod_date = datetime.fromtimestamp(file_mod_time)
    is_outdated = datetime.now() - file_mod_date > timedelta(days=days)
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] OUI file last modified on {file_mod_date}, outdated: {is_outdated}")
    return is_outdated

# Fetch OUI list and apply filters
def fetch_oui_list(url, local_file, filters):
    if args.update_oui or is_oui_file_outdated(local_file):
        update_oui_file(url, local_file)

    if not os.path.exists(local_file):
        print(f"{Fore.RED}❌ [ERROR] OUI file is missing. Exiting. 🔻")
        exit()

    with open(local_file, "r") as file:
        lines = file.readlines()

    filter_keywords = [f.strip().lower() for f in filters.split(",") if f.strip()]
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Filtering OUIs using keywords: {filter_keywords}")



    for line in lines:
        if "(hex)" in line:
            parts = line.split()
            oui = parts[0].replace("-", ":").lower()
            vendor = " ".join(parts[2:])
            if not filter_keywords or any(keyword in vendor.lower() for keyword in filter_keywords):
                oui_list.append(oui)
                vendors[oui] = vendor.strip()

    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] {len(oui_list)} OUIs matched after filtering.")
    print(f"{Fore.GREEN}🔍 [INFO] Found {len(oui_list)} OUIs after filtering. ✅")
    return oui_list, vendors

# Generate random MAC address from OUI
def generate_random_mac(oui):
    mac = f"{oui}:{':'.join(f'{random.randint(0, 255):02x}' for _ in range(3))}"
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Generated random MAC: {mac}")
    return mac


def dhcp_discover(mac, timeout, iface, max_retries):
    retries = 0
    while retries < max_retries:
        try:
            # Construct the DHCP Discover packet
            discover = (
                Ether(src=mac, dst='ff:ff:ff:ff:ff:ff')
                / IP(src='0.0.0.0', dst='255.255.255.255', ttl=128, tos=(4 << 2))
                / UDP(sport=68, dport=67)
                / BOOTP(chaddr=bytes.fromhex(mac.replace(":", "")), xid=random.randint(0, 0xFFFFFFFF))
                / DHCP(options=[
                    ('message-type', 'discover'),
                    ('hostname', 'DESKTOP-XLMCDG'),
                    ('param_req_list', [1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42]),
                    ('end')
                ])
            )
            # Add padding to ensure the packet is at least 300 bytes
            min_length = 300
            padding_needed = max(0, min_length - len(discover))
            if padding_needed > 0:
                discover = discover / Raw(b'\x00' * padding_needed)
            # Send the packet and capture the response
            srp(discover, iface=iface, verbose=0, retry=0, timeout=1)
        except Exception as e:
            if args.debug:
                print(f"{Fore.RED}❗ [ERROR] DHCP discover failed for {mac}: {e}")
        retries += 1
        # In case of EAP, the request is send only once to avoid sending to munch requests
        if mac in eap_tested_mac:
            break
        time.sleep(timeout)  # Optional: Add a small delay between retries



# Test the MAC address for validity
def test_mac(oui, mac, output_file, tested_macs, timeout, iface, debug, vendors, max_retries, force_retry=False):
    """
    Test a single MAC address for validity by sending DHCP Discover requests.
    Optionally listen for EAP failures and retry.
    """
    with lock:
        if mac in tested_macs and not force_retry:
            if debug:
                tqdm.write(f"{Fore.CYAN}🛑 [DEBUG] Skipping previously tested MAC: {mac}")
            return None
        tested_macs.add(mac)

    try:
        randomized_timeout = get_random_timeout(timeout)
        if debug:
            tqdm.write(f"{Fore.CYAN}🐞 [DEBUG] Testing MAC: {mac} with randomized timeout: {randomized_timeout}s")
        dhcp_discover(mac, randomized_timeout, iface, max_retries)

    except Exception as e:
        if debug:
            tqdm.write(f"{Fore.RED}❗ [ERROR] Error testing MAC {mac}: {e}")
    # time.sleep(randomized_timeout)
    return None


# Randomize timeout within ±20% of the provided timeout value
def get_random_timeout(base_timeout, deviation_percent=20):
    deviation = base_timeout * (deviation_percent / 100)
    randomized_timeout = random.uniform(base_timeout - deviation, base_timeout + deviation)
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Calculated randomized timeout: {randomized_timeout}s")
    return randomized_timeout

def main():
    global nb_wait_eap_cycle
    url = "https://standards-oui.ieee.org/oui/oui.txt"
    if args.debug:
        print(f"{Fore.CYAN}🐞 [DEBUG] Starting OUI fetch process with URL: {url}")
    oui_list, vendors = fetch_oui_list(url, args.oui_file, args.filter)
    if not oui_list:
        print(f"{Fore.RED}❌ [ERROR] No OUIs found after filtering. Exiting. 🔻")
        exit()

    
    if os.path.exists(args.output):
        with open(args.output, 'r') as f:
            tested_macs.update(line.split(" | ")[0] for line in f)
        if args.debug:
            print(f"{Fore.CYAN}🐞 [DEBUG] Loaded {len(tested_macs)} previously tested MACs from {args.output}")

    print(f"{Fore.GREEN}🚀 [START] Starting MAC OUI testing with {args.threads} threads... 🔧")

    t_eap = None
    if args.eap:
        t_eap = Thread(target=listen_for_eap, args=(args.iface,))
        t_eap.start()

    t_dhcp = None
    t_dhcp = Thread(target=listen_for_dhcp_offers, args=(args.iface,))
    t_dhcp.start()

    time.sleep(2)
    with tqdm(total=len(oui_list), desc="🧪 Testing OUIs", dynamic_ncols=True, position=0, leave=True) as pbar:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [
                executor.submit(test_mac, oui, generate_random_mac(oui), args.output, tested_macs, args.timeout, args.iface, args.debug, vendors, args.max_retries)
                for oui in oui_list
            ]
            for future in as_completed(futures):
                future.result()
                pbar.update(1)

    zero_cycle = 0
    if args.eap:
        print(f"{Fore.GREEN}🚀 [EAP] Waithing for EAP thread to be finished... 🔧")
        with tqdm(total=len(oui_list), desc="🧪 EAP Cycle in progress (Wait for 0)", dynamic_ncols=True, position=0, leave=True) as pbar2:
            while True:
                time.sleep(10)
                pbar2.n = nb_wait_eap_cycle
                pbar2.update(1)
                if not still_eap_cycle():
                    zero_cycle += 1
                else:
                    zero_cycle = 0
                if zero_cycle >= 6: # Yeah it's for handline some timing issue, just one minute more. If nothing after that, check on wireshark and cut normaly it's finished
                    print("Nothing in EAP stack ... you should Ctrl+C")

    print(f"{Fore.GREEN}🎉 [FINISHED] MAC OUI testing completed. ✅")


if __name__ == "__main__":
    main()
