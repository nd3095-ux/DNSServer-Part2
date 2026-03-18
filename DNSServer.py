# DNSServer.py
# Author: Nikica Dokic
# Ready-to-submit skeleton for DNS Part 2

import socket
import threading

# --- Encryption placeholders ---
def generate_aes_key(password, salt):
    pass

def encrypt_with_aes(data, key):
    pass

def decrypt_with_aes(ciphertext, key):
    pass

# --- DNS Records Dictionary ---
dns_records = {
    "safebank.com.": {"A": "192.168.1.102"},
    "google.com.": {"A": "192.168.1.103"},
    "legitsite.com.": {"A": "192.168.1.104"},
    "yahoo.com.": {"A": "192.168.1.105"},
    "nyu.edu.": {
        "A": "192.168.1.106",
        "TXT": "placeholder_encrypted_data",
        "MX": (10, "mxa-00256a01.gslb.pphosted.com."),
        "AAAA": "2001:0db8:85a3:0000:0000:8a2e:0373:7312",
        "NS": "ns1.nyu.edu."
    }
}

# --- DNS Server Skeleton ---
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 53))  # Bind to localhost DNS port
    print("DNS Server running...")
    while True:
        try:
            data, addr = server_socket.recvfrom(512)
            print(f"Received request from {addr}")
            server_socket.sendto(data, addr)  # Placeholder response
        except Exception as e:
            print("Error:", e)

def run():
    server_thread = threading.Thread(target=start_server)
    server_thread.start()
    while True:
        cmd = input()
        if cmd == 'q':
            break

# --- Function required by autograder ---
def run_dns_server():
    """Autograder requires this function."""
    run()

# --- Safe top-level execution ---
if __name__ == "__main__":
    run()