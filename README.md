# Smart Network Traffic Analzyer

A python-based tool developed by Alex Olener and Wes Ihuezo for CPS344 Computer Networks. This is out final project and the aim is to try to understand and automate the detection of Indicators of Compromise (IoC) within a network packet capture.

---

## Overview

The **Smart Network Traffic Analyzer** uses the `Pyshark` library to streamline the process of analyzing `.pcap` and `.pcapng` files as an alternative to manually using WireShark to get the packet data

## Key Analysis:
* **DNS Query:** Checks if the queries for DNS are directed to a trusted server
* **External Communication:** Automatically can filter intenal network noise in order to find commonly used paths on the open network
* **Protocol Distribution:** The program automatically can break down the traffic patterns within a capture (e.g. HTTP, TLS, etc.)

---

## Technical Setup

### Prerequisite:
* **Wireshark/Tshark:** Must both be installed on the system (Pyshark is a python wrapper for `tshark`)
* **Python 3.xx**

### Installation
1. Clone the repository or download `analyze.py`
2. Install dependencies: 
```bash pip install pyshark```

### How to Run:
``python analyze.py your_capture_file.pcap``

