import scapy.all as scapy
from scapy.layers.dot11 import Dot11, Dot11Beacon

def wifi_security_analyzer(interface):
    networks = {}

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Beacon].info.decode(errors='ignore')
            bssid = packet[Dot11].addr2
            stats = packet[Dot11Beacon].network_stats()
            encryption = stats.get("crypto", "Open")

            signal_strength = getattr(packet, 'dBm_AntSignal', 'N/A')

            if bssid not in networks:
                networks[bssid] = (ssid, encryption, signal_strength)
                print(f"SSID: {ssid}, BSSID: {bssid}, Encryption: {encryption}, Signal: {signal_strength}")

    print("Scanning WiFi networks...")
    scapy.sniff(iface=interface, prn=packet_handler, store=False)

if __name__ == "__main__":
    wifi_security_analyzer("wlan0")
