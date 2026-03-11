# Python Packet Sniffer

# Warning
This repository is solely for reasearch and learning purposes. This tool performs packet capturing and network analysis. Running this against networks u do not own or have permission for could be illegal.

A Python-based network traffic analysis tool built using Scapy.

The program captures and processes packets in real time, extracting key
metadata and analyzing traffic patterns to identify potentially malicious
behavior such as port scans and denial-of-service activity.

A lightweight GUI dashboard displays packet data, alerts, and suspicious
activity as it is detected.

## Example Output

### Live Dashboard
<p align="center">
  <img src="https://github.com/user-attachments/assets/291cdc92-7a6d-47fc-8bab-938c790df6d3" width="900" alt="Packet Sniffer GUI"/>
</p>

### Terminal Output
<p align="center">
  <img src="https://github.com/user-attachments/assets/ac2c7ca1-8841-469c-a5b3-5dec496c3437" width="500" alt="Packet Sniffer Terminal Output"/>
</p>

## Features


- Detects horizontal port scans (one source probing many devices on the same port)
- Detects vertical port scans (one source probing many ports on a single device)
- Detects sequential port scans (ordered port sweeps commonly used by automated scanners)
- Basic DDoS detection based on rapid repeated requests from a source
- Real-time packet inspection and classification
- Synthetic traffic generation for testing attack scenarios
- Unit tests to ensure functionality and edge cases
- Tracks suspicious IP addresses and assigns severity levels to incoming packets

## Structure
- python-packet-sniffer/
- main.py           # entrypoint (CLI / GUI)
- sniffer.py        # packet capture & parsing
- detection.py      # scan & rate detection logic
- gui.py            # dashboard
- requirements.txt 
- sample_output.txt
- pcaps/            # optional: example PCAPs for testing
- screenshots/
- tests/            # pytest unit tests

## Why I Built This

This project was created to better understand how network intrusion detection systems detect malicious traffic patterns and to practice implementing real-time analysis using Python.

## Run It Yourself

### Prerequisites
  Requires Adminsitor access or elevated access
  ### Windows Users

Packet capture requires Npcap.  
If packet sniffing does not work, install it from:

https://npcap.com/

### Installation

1. Clone the repository

```bash
git clone https://github.com/JoshWestenheffer/python-packet-sniffer.git
```

2. Navigate to the project folder

```bash
cd python-packet-sniffer
```

3. Install dependencies

```bash
pip install -r requirements.txt
```

### Running the Program

Start the packet sniffer:

```bash
python main.py
```

> Note: Packet sniffing may require administrator/root privileges depending on your system.

