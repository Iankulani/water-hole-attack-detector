# -*- coding: utf-8 -*-
"""
Created on Fri Feb  21 03:345:47 2025

@author: IAN CARTER KULANI

"""

from colorama import Fore
import pyfiglet
import os
font=pyfiglet.figlet_format("Water Hole Attack Detector")
print(Fore.GREEN+font)

import scapy.all as scapy
import socket
import time

# Function to get user input for WAP IP Address
def get_wap_ip():
    wap_ip = input("Enter WAP IP Address to check for potential Water Hole attack:")
    return wap_ip

# Function to perform a basic scan of the network and check for DNS anomalies
def detect_water_hole_attack(wap_ip):
    print(f"Checking WAP IP: {wap_ip} for potential Water Hole attack...")
    
    # Use scapy to sniff packets from the network
    print("Starting packet sniffing...")
    scapy.sniff(prn=analyze_packet, store=0, filter=f"host {wap_ip}", timeout=60)

# Analyze each packet to look for DNS anomalies or suspicious patterns
def analyze_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        
        # Check if packet has DNS layer
        if packet.haslayer(scapy.DNS):
            # If we detect DNS request/response, check for anomalies
            if packet[scapy.DNS].qr == 0:  # Query packet
                query = packet[scapy.DNS].qd.qname
                print(f"DNS Query: {query} from {ip_src} to {ip_dst}")
                check_for_suspicious_dns(query, ip_src)
            elif packet[scapy.DNS].qr == 1:  # Response packet
                print(f"DNS Response from {ip_dst}")
                check_for_suspicious_dns(packet[scapy.DNS].an.rdata, ip_dst)

# Function to identify suspicious DNS traffic
def check_for_suspicious_dns(dns_entry, ip):
    # Example suspicious DNS: unexpected redirects or strange domain names
    suspicious_domains = ["evilsite.com", "fake.com", "malicious.com"]
    
    if any(domain in dns_entry for domain in suspicious_domains):
        print(f"WARNING: Suspicious DNS detected! {dns_entry} from IP {ip}")
    else:
        print(f"DNS traffic seems normal: {dns_entry} from IP {ip}")

# Main function
def main():
    wap_ip = get_wap_ip()  # Get the WAP IP address from the user
    detect_water_hole_attack(wap_ip)  # Start detection

# Run the program
if __name__ == "__main__":
    main()
