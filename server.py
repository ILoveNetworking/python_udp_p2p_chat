# UDP peer-to-peer chat rendezvous server

import os
import sys
import rsa
import pickle
from base64 import b64decode, b64encode
import socket
import threading

BIND_ADRESS = ("0.0.0.0", 65500)

certfile = "./certs/public.key"
cert_folder = "./certs"

def check_cert_path() -> None:
    """
    This function checks if public and private keys exists\n
    Arguments : None\n 
    Returns : None
    """
    if not os.path.exists(certfile):
        print("[!] No server certificate found!")
        print("[+] Generating server private and public keys")
        pub, priv = rsa.newkeys(2048, exponent=65535)
        if not os.path.exists(cert_folder):
            os.mkdir(cert_folder)
        else:
            return
        with open(os.path.join(cert_folder, "public.key"), "w") as kf:
            kf.write(b64encode(pickle.dumps(pub)).decode())
        with open(os.path.join(cert_folder, "private.key"), "w") as cf:
            cf.write(b64encode(pickle.dumps(priv)).decode())
        print(f"[+] Keys generatet and written to: {cert_folder}/")
        print("[+] Use some safe way to transfer public key to the client")


def start_server() -> None:
    """
    This function starts the rendezvous server\n
    Arguments : None\n
    Returns : None
    """
    priv_key = ""
    with open(os.path.join(cert_folder, "private.key"), "r") as cf:
        priv_key = pickle.loads(b64decode(cf.read()))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(BIND_ADRESS)
    print(f"[+] Starting a rendezvous server at: {BIND_ADRESS}")

    # creating SSL socket
    # listening for incoming data
    clients = []
    while True:

        data, address = sock.recvfrom(2048)
        # data = data.decode()

        result = []
        for n in range(0,len(data),256):
            part = data[n:n+256]
            result.append( rsa.decrypt(part, priv_key).decode() )

        decrypted = ''.join(result)
        print(decrypted)

        if "KEY" in decrypted.strip(): # here client send it's public key after check
            print(f"[+] Connection from peer: {address}")
            client_pub_key = pickle.loads(b64decode(decrypted.strip().split()[-1]))
            packet = str(len(decrypted.strip())).encode()
            enc_packet = rsa.encrypt(packet, client_pub_key)
            sock.sendto(enc_packet, address)
            clients.append([address, client_pub_key])
        
        if len(clients) == 2:
            c1 = clients[0]
            c2 = clients[1]
            print(f"Exchanging: {c1[0]} <-> {c2[0]}")
            # exchanging the address:port:public_key between clients
            packet_for_c2 = f"{c1[0][0]}:{c1[0][1]}:{b64encode(pickle.dumps(c1[1])).decode()}".encode()

            result = []
            for n in range(0, len(packet_for_c2), 245):
                part = packet_for_c2[n:n+245]
                result.append( rsa.encrypt(part, c2[1]) )
            enc_packet_for_c2 = b''.join(result)
            sock.sendto(enc_packet_for_c2, c2[0])
            
            packet_for_c1 = f"{c2[0][0]}:{c2[0][1]}:{b64encode(pickle.dumps(c2[1])).decode()}".encode()
            result = []
            for n in range(0, len(packet_for_c1), 245):
                part = packet_for_c1[n:n+245]
                result.append( rsa.encrypt(part, c1[1]) )
            enc_packet_for_c1 = b''.join(result)
            sock.sendto(enc_packet_for_c1, c1[0])

            clients = []


if __name__ == "__main__":
    try:
        check_cert_path()
        start_server()
    except KeyboardInterrupt:
        print("[+] KeyboardInterrupt detected. Exiting the program...")