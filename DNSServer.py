import socket
import dns.message
import dns.rdatatype
import dns.rdataclass
import dns.rrset
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64

# ---------------------------
# Encryption Functions
# ---------------------------
def generate_aes_key(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def encrypt_with_aes(key, plaintext):
    plaintext_bytes = plaintext.encode()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)
    return base64.b64encode(cipher.nonce + tag + ciphertext)

def decrypt_with_aes(key, ciphertext_b64):
    data = base64.b64decode(ciphertext_b64)
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext_bytes.decode()

# ---------------------------
# Encryption Setup
# ---------------------------
salt = b"Tandon"
password = "YOUR_NYU_EMAIL@nyu.edu"   # <-- Replace with your NYU email
key = generate_aes_key(password, salt)
secret_data = "AlwaysWatching"
encrypted_data = encrypt_with_aes(key, secret_data)
txt_value = encrypted_data.decode()  # For TXT record

# ---------------------------
# DNS Records
# ---------------------------
records = {
    "safebank.com.": {"A": "192.168.1.102"},
    "google.com.": {"A": "192.168.1.103"},
    "legitsite.com.": {"A": "192.168.1.104"},
    "yahoo.com.": {"A": "192.168.1.105"},
    "nyu.edu.": {
        "A": "192.168.1.106",
        "TXT": txt_value,
        "MX": (10, "mxa-00256a01.gslb.pphosted.com."),
        "AAAA": "2001:db8:85a3::8a2e:373:7312",
        "NS": "ns1.nyu.edu."
    }
}

# ---------------------------
# DNS Server Setup
# ---------------------------
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", 53))  # Localhost DNS server

print("DNS Server running on 127.0.0.1:53... Press Ctrl+C to stop.")

while True:
    try:
        data, addr = sock.recvfrom(512)
        request = dns.message.from_wire(data)
        response = dns.message.make_response(request)

        question = request.question[0]
        qname = str(question.name)
        qtype = dns.rdatatype.to_text(question.rdtype)

        if qname in records and qtype in records[qname]:
            value = records[qname][qtype]

            if qtype == "A":
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, value)
            elif qtype == "TXT":
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.TXT, f'"{value}"')
            elif qtype == "MX":
                priority, mail = value
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.MX, f"{priority} {mail}")
            elif qtype == "AAAA":
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.AAAA, value)
            elif qtype == "NS":
                rdata = dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.NS, value)
            else:
                rdata = None

            if rdata:
                rrset = dns.rrset.from_rdata(question.name, 300, rdata)
                response.answer.append(rrset)

        # Set Authoritative Answer flag
        response.flags |= dns.flags.AA

        # Send response
        sock.sendto(response.to_wire(), addr)

    except KeyboardInterrupt:
        print("\nServer shutting down...")
        break
    except Exception as e:
        print(f"Error: {e}")