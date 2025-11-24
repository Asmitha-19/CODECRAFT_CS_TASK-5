Packet Sniffer (Python + Scapy)

A lightweight Python-based Packet Sniffer built using Scapy, capable of capturing, analyzing, and inspecting network packets in real-time.
Supports saving captured packets, reading from .pcap files, and filtering specific protocols.

✨ Features

Capture live network packets

Filter packets by protocol (TCP / UDP / ICMP)

Display packet summary

Save captured packets to .pcap

Load & analyze .pcap files

Auto-makes output directory

Fully CLI-based (argparse)

📦 Installation
1️⃣ Install Dependencies
pip install scapy

2️⃣ Run the Sniffer
sudo python main.py


⚠️ sudo required for real-time packet sniffing.

📌 Usage
▶️ Capture Packets
sudo python main.py --capture 10

▶️ Filter by protocol
sudo python main.py --capture 20 --filter tcp

▶️ Read from PCAP
python main.py --read sample.pcap

▶️ Save Captured Packets
sudo python main.py --capture 15 --save

📁 Project Structure
packet-sniffer/
│── main.py
│── output/
│     └── packet_capture.pcap

❗ Requirements

Python 3.8+

Scapy

Root permissions for live capture

📝 License

MIT License — free to use and modify.
