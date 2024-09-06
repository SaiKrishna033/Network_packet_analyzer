Here’s the updated `README.md` file including a section with a sample output:

---

# Network_packet_analyzer Tool

This Python-based packet sniffer captures and analyzes network packets. It provides detailed information such as source and destination IP addresses, protocols, ports, and packet payloads. The tool is designed for educational purposes and logs captured packet data into a well-organized output file.

## Features
- Captures and logs network packets in real-time.
- Displays key information including:
  - Timestamp
  - Source and Destination IP addresses
  - Protocol (TCP, UDP, ICMP)
  - Source and Destination Ports
  - Packet Payload (truncated for long payloads)
- Outputs data to a formatted text file with dynamically adjustable column sizes for better readability.

## Requirements
- Python 3.x
- Scapy library
- Psutil library

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/Network_packet_analyzer.git
   cd Network_packet_analyzer
   ```

2. Install the required Python packages:
   ```bash
   pip install scapy psutil
   ```

## Usage

1. List available network interfaces:
   ```bash
   python Network_packet_analyzer.py
   ```

2. Select the interface number to start sniffing:
   - The tool will start capturing packets and log the output to a text file.

3. Stop packet capture using `Ctrl + C`.

## Sample Output

The packet data is logged into `packet_log.txt` in a formatted table with columns for timestamp, source/destination IP, protocol, ports, and payload.

Example of the output:

```
+---------------------+-----------------+-----------------+----------+-------------+-----------------+----------------------------------------------------+
|     Timestamp       |   Source IP      | Destination IP  | Protocol | Source Port | Destination Port|                     Payload                         |
+---------------------+-----------------+-----------------+----------+-------------+-----------------+----------------------------------------------------+
| 2024-09-06 14:23:45 | 192.168.1.10     | 192.168.1.1     |   TCP    |     443     |       54736     | GET /index.html HTTP/1.1                            |
| 2024-09-06 14:23:46 | 192.168.1.15     | 192.168.1.10    |   UDP    |     53      |       49782     | DNS Query: www.example.com                          |
| 2024-09-06 14:23:47 | 192.168.1.20     | 192.168.1.1     |   ICMP   |             |                 | ICMP Echo Request                                   |
+---------------------+-----------------+-----------------+----------+-------------+-----------------+----------------------------------------------------+
```

The payload is truncated if it exceeds the predefined column size for better readability. The output file dynamically adjusts the column widths based on the content.
