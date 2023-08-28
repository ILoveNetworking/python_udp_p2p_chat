# UDP peer-to-peer chat rendezvous server

import sys
import socket
import threading

BIND_ADRESS = ("0.0.0.0", 65500)

def start_server() -> None:
    """
    This function starts the rendezvous server\n
    Arguments : None\n
    Returns : None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(BIND_ADRESS)
    print(f"[+] Starting a rendezvous server at: {BIND_ADRESS}")

    # listening for incoming data
    clients = []
    while True:

        data, address = sock.recvfrom(256)
        data = data.decode()

        if data.strip() == "check":
            print(f"[+] Connection from peer: {address}")
            packet = str(len(data.strip())).encode()
            sock.sendto(packet, address)
            clients.append(address)
        
        if len(clients) == 2:
            c1 = clients[0]
            c2 = clients[1]
            print(f"Exchanging: {c1} <-> {c2}")
            packet_for_c2 = f"{c1[0]}:{c1[1]}".encode()
            sock.sendto(packet_for_c2, c2)
            packet_for_c1 = f"{c2[0]}:{c2[1]}".encode()
            sock.sendto(packet_for_c1, c1)

            clients = []


if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("[+] KeyboardInterrupt detected. Exiting the program...")