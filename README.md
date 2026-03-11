# Python Packet Sniffer

A Python-based network traffic analysis tool built using Scapy.

The program captures and processes packets in real time, extracting key
metadata and analyzing traffic patterns to identify potentially malicious
behavior such as port scans and denial-of-service activity.

A lightweight GUI dashboard displays packet data, alerts, and suspicious
activity as it is detected.

## Example Output

<p align="center">
  <img src="https://github.com/user-attachments/assets/ee90b1e9-4c48-483b-9b3d-bb103cae0f4c" width="700"/>
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

## Why I Built This

This project was created to better understand how network intrusion detection systems detect malicious traffic patterns and to practice implementing real-time analysis using Python.

