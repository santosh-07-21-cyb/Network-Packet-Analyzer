# Network-Packet-Analyzer
A simple python-based network packet analyzer built using **Python and Scapy** that captures and analyzes live network traffic. The tool identifies network protocols, displays packet information, maintains traffic statistics, and allows filtering captured packets based on protocol type.



## Features

- Live packet capture from the network interface
- Displays source and destination IP addresses
- Detects network protocols:
  - TCP
  - UDP
  - ICMP
  - Other protocols
- Displays source and destination ports
- Shows packet size
- Maintains packet statistics
- Filters captured packets by protocol
  


## Technologies Used

- Python
- **Library:** Scapy
- **Concepts Used:**
  - Network packet sniffing
  - IP packet analysis
  - Protocol identification
  - Traffic monitoring


## Installation

```bash
pip install scapy
```
## Usage

```bash
python3 security_scanner.py
```

## Sample Output

### Step 1: Entering number of packets to capture under a given time(seconds)

<img width="772" height="717" alt="sc1" src="https://github.com/user-attachments/assets/459b6d45-090a-4f19-a61a-c1757a3c14bf" />


### Step 2: Display of various packets and its statistics 

<img width="502" height="377" alt="sc2" src="https://github.com/user-attachments/assets/d7a1ffe6-511d-43c6-ad37-731c42041328" />


### Step3: Display of Specific packet selected and its statistics

<img width="587" height="691" alt="sc3" src="https://github.com/user-attachments/assets/6ab7637c-3f29-4db1-b000-f823feb9d494" />

