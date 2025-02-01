import socket
import struct
import time
import json
import threading
from tkinter import Tk, Button, filedialog, messagebox
from scapy.all import wrpcap, Ether

# Lista de pacotes capturados
packets = []
scapy_packets = []

# Portas críticas comuns
critical_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 443: "HTTPS"}

# Função para processar pacotes
def process_packet(packet):
    global scapy_packets
    timestamp = time.time()
    
    eth_packet = Ether(packet)
    scapy_packets.append(eth_packet)  # Armazena para salvar em PCAP

    eth_header = packet[:14]
    eth_data = struct.unpack("!6s6sH", eth_header)
    eth_protocol = socket.ntohs(eth_data[2])

    if eth_protocol == 8:  # Se for IPv4
        ip_header = packet[14:34]
        iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

        protocol = iph[6]
        src_ip = socket.inet_ntoa(iph[8])
        dest_ip = socket.inet_ntoa(iph[9])

        if protocol == 1:  # ICMP
            packets.append({"timestamp": timestamp, "protocol": "ICMP", "src_ip": src_ip, "dest_ip": dest_ip})

        elif protocol == 6:  # TCP
            tcp_header = packet[34:54]
            tcph = struct.unpack("!HHLLBBHHH", tcp_header)
            src_port = tcph[0]
            dest_port = tcph[1]
            alert = "CRITICAL PORT DETECTED" if src_port in critical_ports or dest_port in critical_ports else "Normal"

            packets.append({"timestamp": timestamp, "protocol": "TCP", "src_ip": src_ip, "dest_ip": dest_ip, "src_port": src_port, "dest_port": dest_port, "alert": alert})

        elif protocol == 17:  # UDP
            udp_header = packet[34:42]
            udph = struct.unpack("!HHHH", udp_header)
            src_port = udph[0]
            dest_port = udph[1]

            # Identificar DNS (porta 53)
            if src_port == 53 or dest_port == 53:
                packets.append({"timestamp": timestamp, "protocol": "DNS", "src_ip": src_ip, "dest_ip": dest_ip, "src_port": src_port, "dest_port": dest_port})
            else:
                packets.append({"timestamp": timestamp, "protocol": "UDP", "src_ip": src_ip, "dest_ip": dest_ip, "src_port": src_port, "dest_port": dest_port})

# Função para capturar pacotes
def packet_sniffer():
    raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        packet, _ = raw_socket.recvfrom(65565)
        process_packet(packet)

# Iniciar a captura de pacotes em uma thread separada
sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
sniffer_thread.start()

# Função para salvar JSON
def save_json():
    file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
    if file_path:
        with open(file_path, "w") as f:
            json.dump(packets, f, indent=4)
        messagebox.showinfo("Sucesso", f"Pacotes salvos em {file_path}")

# Função para salvar PCAP
def save_pcap():
    file_path = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP files", "*.pcap")])
    if file_path:
        wrpcap(file_path, scapy_packets)
        messagebox.showinfo("Sucesso", f"Pacotes salvos em {file_path}")

# Interface gráfica
root = Tk()
root.title("Sniffer de Pacotes")

Button(root, text="Salvar como JSON", command=save_json, width=20).pack(pady=10)
Button(root, text="Salvar como PCAP", command=save_pcap, width=20).pack(pady=10)

root.mainloop()
