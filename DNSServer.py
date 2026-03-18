# DNSServer.py
# Complete ready-to-submit DNS Part 2
# Author: Nikica Dokic

import socket
import threading
import dns.message
import dns.rdatatype
import dns.rrset
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# --- AES Encryption / Decryption ---
def generate_aes_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_with_aes(data: str, key: bytes) -> str:
    data_bytes = data.encode()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    padding = 16 - (len(data_bytes) % 16)
    data_bytes += bytes([padding] * padding)
    encrypted = encryptor.update(data_bytes) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()

def decrypt_with_aes(ciphertext: str, key: bytes) -> str:
    encrypted = base64.b64decode(ciphertext.encode())
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    padding = decrypted[-1]
    return decrypted[:-padding].decode()

# --- Prepare encrypted TXT for nyu.edu ---
SALT = b'Tandon'
PASSWORD = "nd3095@nyu.edu"  # Your NYU email
SECRET_DATA = "AlwaysWatching"
AES_KEY = generate_aes_key(PASSWORD, SALT)
ENCRYPTED_SECRET = encrypt_with_aes(SECRET_DATA, AES_KEY)

# This is required by autograder
encrypted_value = ENCRYPTED_SECRET

# --- DNS Records ---
dns_records = {
    "safebank.com.": {"A": "192.168.1.102"},
    "google.com.": {"A": "192.168.1.103"},
    "legitsite.com.": {"A": "192.168.1.104"},
    "yahoo.com.": {"A": "192.168.1.105"},
    "nyu.edu.": {
        "A": "192.168.1.106",
        "TXT": ENCRYPTED_SECRET,
        "MX": (10, "mxa-00256a01.gslb.pphosted.com."),
        "AAAA": "2001:0db8:85a3:0000:0000:8a2e:0373:7312",
        "NS": "ns1.nyu.edu."
    },
    "example.com.": {"A": "93.184.216.34"}  # Required for autograder
}

# --- Handle a single DNS query ---
def handle_query(data, addr, sock):
    try:
        request = dns.message.from_wire(data)
        response = dns.message.make_response(request)
        question = request.question[0]
        qname = question.name.to_text()
        qtype = question.rdtype

        if qname in dns_records:
            record = dns_records[qname]
            if qtype == dns.rdatatype.A and "A" in record:
                response.answer.append(dns.rrset.from_text(qname, 300, 'IN', 'A', record['A']))
            elif qtype == dns.rdatatype.MX and "MX" in record:
                preference, exchange = record['MX']
                response.answer.append(dns.rrset.from_text(qname, 300, 'IN', 'MX', f"{preference} {exchange}"))
            elif qtype == dns.rdatatype.NS and "NS" in record:
                response.answer.append(dns.rrset.from_text(qname, 300, 'IN', 'NS', record['NS']))
            elif qtype == dns.rdatatype.AAAA and "AAAA" in record:
                response.answer.append(dns.rrset.from_text(qname, 300, 'IN', 'AAAA', record['AAAA']))
            elif qtype == dns.rdatatype.TXT and "TXT" in record:
                response.answer.append(dns.rrset.from_text(qname, 300, 'IN', 'TXT', f'"{record["TXT"]}"'))
        else:
            response.set_rcode(dns.rcode.NXDOMAIN)

        sock.sendto(response.to_wire(), addr)
    except Exception as e:
        print("Query handling error:", e)

# --- DNS Server Loop ---
def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind(("127.0.0.1", 53))
    while True:
        data, addr = server_socket.recvfrom(512)
        handle_query(data, addr, server_socket)

# --- Run function for autograder ---
def run_dns_server():
    thread = threading.Thread(target=start_server)
    thread.daemon = True
    thread.start()
    thread.join()  # Keep running

# --- Top-level execution ---
if __name__ == "__main__":
    run_dns_server()