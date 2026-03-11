# python-packet-sniffer

This is a Python coded network traffic analysis tool that utilizes Scapy as the main packet sniffer. It catalogs impoortant data from these packets while searching for malicious intent. <br>
The packet sniffer uses a gui dashboard for easy readability and live updating. 

The program processes network packets in real time and identifies suspicious patterns using behavioral analysis techniques. <br>
It was built to explore how intrusion detection systems monitor network activity and detect abnormal traffic patterns.

Features:
  Detects horizontal port scans (one source probing many devices on the same port) <br>
  Detects vertical port scans (one source probing many ports on a single device) <br>
  Detects sequential port scans (ordered port sweeps commonly used by automated scanners) <br>
  Basic DDoS detection based on rapid repeated requests from a source <br>
  Real-time packet inspection and classification <br>
  Synthetic traffic generation for testing attack scenarios <br>
  Unit test to ensure functionality and edge cases <br>
  Tracks suspicious IP addresses and assigns severity levels to incoming packets <br>
