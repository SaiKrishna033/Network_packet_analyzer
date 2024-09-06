import psutil
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Path to the text file
LOG_FILE = "packet_log.txt"

def list_interfaces():
    interfaces = psutil.net_if_addrs()
    print("Available network interfaces:")
    interface_names = list(interfaces.keys())
    for index, iface in enumerate(interface_names):
        print(f"{index}: {iface}")
    return interface_names

def write_to_file(log_entry):
    with open(LOG_FILE, "a") as file:
        file.write(f"| {log_entry['Timestamp']:19} | {log_entry['Source IP']:15} | {log_entry['Destination IP']:15} | {log_entry['Protocol']:8} | {log_entry['Source Port']:11} | {log_entry['Destination Port']:11} | {log_entry['Payload']:50} |\n")

def initialize_file():
    with open(LOG_FILE, "w") as file:
        file.write("+" + "-"*21 + "+" + "-"*17 + "+" + "-"*17 + "+" + "-"*9 + "+" + "-"*13 + "+" + "-"*13 + "+" + "-"*52 + "+\n")
        file.write("| Timestamp           | Source IP       | Destination IP  | Protocol | Source Port  | Destination Port | Payload                                             |\n")
        file.write("+" + "-"*21 + "+" + "-"*17 + "+" + "-"*17 + "+" + "-"*9 + "+" + "-"*13 + "+" + "-"*13 + "+" + "-"*52 + "+\n")

def analyze_packet(packet):
    log_entry = {
        'Timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'Source IP': '',
        'Destination IP': '',
        'Protocol': '',
        'Source Port': '',
        'Destination Port': '',
        'Payload': ''
    }
    
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        log_entry['Source IP'] = ip_layer.src
        log_entry['Destination IP'] = ip_layer.dst
        log_entry['Protocol'] = ip_layer.proto

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            log_entry['Source Port'] = tcp_layer.sport
            log_entry['Destination Port'] = tcp_layer.dport
            if packet.haslayer(Raw):
                log_entry['Payload'] = str(packet[Raw].load)

        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            log_entry['Source Port'] = udp_layer.sport
            log_entry['Destination Port'] = udp_layer.dport
            if packet.haslayer(Raw):
                log_entry['Payload'] = str(packet[Raw].load)

        elif packet.haslayer(ICMP):
            log_entry['Protocol'] = 'ICMP'
        
        write_to_file(log_entry)

def start_sniffing(interface):
    print(f"Starting packet capture on interface {interface}... Logging to {LOG_FILE}")
    print("Press Ctrl + C to stop.")
    initialize_file()
    try:
        sniff(iface=interface, prn=analyze_packet, store=0)
    except KeyboardInterrupt:
        print("\nPacket capture stopped.")

if __name__ == "__main__":
    interface_names = list_interfaces()
    index = int(input("Enter the number of the network interface to sniff: "))
    if 0 <= index < len(interface_names):
        interface = interface_names[index]
        start_sniffing(interface)
    else:
        print("Invalid interface number.")
