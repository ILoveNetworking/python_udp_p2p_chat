# Udp peer-to-peer chat client

import os
import sys
import socket
import threading
from random import randint

# Rendezvous server connection information
RENDEZVOUS_DATA = ("127.0.0.1", 65500) # Connect to localhost for now
# Port on which peers will be connected to each other
LISTENER_PEER_PORT = randint(50000, 65535)

def connect_to_rendezvous() -> tuple:
    """
    This function connects to the rendezvous server to get the other peer connection data\n
    Arguments : None\n
    Returns : tuple(str(remote_peer_ip), int(remote_peer_port))
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTENER_PEER_PORT))

    control_packet = b"check"
    control_packet_len = len(control_packet)
    sock.sendto(control_packet, RENDEZVOUS_DATA)

    while True:
        response = sock.recv(256)
        response = int(response.decode())
        if response == control_packet_len:
            print(f"[+] Got response from server. Waiting another peer...")
            break
    
    peer_data = sock.recv(256)
    peer_data = peer_data.decode()
    print(f"[+] Recieved peer: {peer_data}")
    ip,port = peer_data.split(":")
    port = int(port)
    sock.close()

    return (ip, port)

def start_listener() -> None:
    """
    This function run a listener in separate thread for incoming messages on LISTENER_PEER_PORT\n
    Arguments : None\n
    Returns : None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTENER_PEER_PORT))
    
    # recieving messages here
    while True:
        msg, address = sock.recvfrom(1024)

        if "FILE" in msg.decode().strip():
            _, length, name = msg.decode().strip().split()
            print(f"[+] Requested a file upload: {name} with length: {length}b")
            file_data = sock.recv(int(length) + 128)
            with open(f"./{name}", "wb") as f:
                f.write(file_data)
            print(f"[+] File written: ./{name}\n> ")
            continue

        print(f"\r[{address[0]}:{address[1]}]: {msg.decode()}\n> ", end="")

def send_msgs(con_data : tuple) -> None:
    """
    This function sends messages to the remote peer\n
    Arguments : tuple(str(remote_ip), int(remote_port))\n
    Returns : None
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # because this is the sender socket, we can bind it to any port we want or use 1 higher than listener
    sock.bind(("0.0.0.0", LISTENER_PEER_PORT + 1))
    print("[+] Type \help or \? to see list of available commands")
    # main message sending loop
    while True:
        message = input("> ")

        # implementing some menu commands
        if message.strip() == "\quit":
            print("[+] Quit command detected. Exiting...")
            sock.close()
            return
        elif message.strip() == "\help" or message.strip() == "\?":
            print("[+] List of commands:")
            print("[+] \help or \? - This hint")
            print("[+] \send_file <path to a file> - Send a file to remote peer client")
            print("[+] \quit - exit the program")
            continue
        elif len(message.strip().split()) == 2:
            if message.strip().split()[0] == "\send_file":
                _, file_path = message.strip().split()
                if os.path.exists(file_path):
                    file_data = None
                    with open(file_path, "rb") as f:
                        file_data = f.read()
                    file_length = len(file_data)
                    file_name = file_path.split("/")[-1]
                    control_packet = f"FILE {file_length} {file_name}".encode()
                    sock.sendto(control_packet, con_data)
                    sock.sendto(file_data, con_data)
                    continue
                else:
                    print(f"[+] Invalid path: {file_path}")
                    continue

        sock.sendto(message.encode(), con_data)

if __name__ == "__main__":
    # connecting to rendezvous server to check in on server
    peer_data = connect_to_rendezvous()
    # start listener loop
    l_thread = threading.Thread(target=start_listener)
    l_thread.daemon = True
    l_thread.start()
    # Send messages to the remote peer
    send_msgs(peer_data)