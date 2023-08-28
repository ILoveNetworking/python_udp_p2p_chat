# Udp peer-to-peer chat client

import os
import sys
import rsa
import pickle
from base64 import b64decode, b64encode
import socket
import threading
from random import randint

# Rendezvous server connection information
RENDEZVOUS_DATA = ("127.0.0.1", 65500) # Connect to localhost for now
# Port on which peers will be connected to each other
LISTENER_PEER_PORT = randint(50000, 65535)

# Creating public private keys
print("[+] Generating keypair for this session...")
pub, priv = rsa.newkeys(2048)
print("[+] Done!")

# Assuming we are know the server public key
server_pub_key = ""

if os.path.exists("./certs/public.key"):
    with open("./certs/public.key", "r") as spkf:
        server_pub_key = pickle.loads(b64decode(spkf.read()))

if server_pub_key == "":
    print("[!] Failed to load server public key!")
    print("[!] Please validate path")
    sys.exit(-1)

def connect_to_rendezvous() -> list:
    """
    This function connects to the rendezvous server to get the other peer connection data\n
    Arguments : None\n
    Returns : list(tuple(str(remote_peer_ip), int(remote_peer_port)), PublicKey(remote_peer_public))
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTENER_PEER_PORT))

    based_pub_key = b64encode(pickle.dumps(pub)).decode()
    control_packet = ("KEY " + based_pub_key).encode()
    control_packet_len = len(control_packet)

    # Workaround RSA encryption length, max chunck length 245
    result = []
    for n in range(0, control_packet_len, 245):
        part = control_packet[n:n+245]
        result.append( rsa.encrypt(part, server_pub_key) )
    enc_control_packet = b''.join(result)

    sock.sendto(enc_control_packet, RENDEZVOUS_DATA)

    while True:
        response = sock.recv(1024)
        dec_resp = rsa.decrypt(response, priv).decode()
        pack_len = int(dec_resp)
        if pack_len == control_packet_len:
            print(f"[+] Got response from server. Waiting another peer...")
            break
    
    peer_data = sock.recv(2048)
    result = []
    for n in range(0,len(peer_data),256):
        part = peer_data[n:n+256]
        result.append( rsa.decrypt(part, priv).decode("ascii") )

    peer_data = ''.join(result)

    print(f"[+] Recieved peer: {peer_data}")
    ip,port,remote_peer_pub = peer_data.split(":")
    remote_peer_pub = pickle.loads(b64decode(remote_peer_pub))
    port = int(port)
    sock.close()

    return [(ip, port), remote_peer_pub]

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
        decrypted = rsa.decrypt(msg, priv).decode()

        if "FILE" in decrypted.strip():
            _, length, name = decrypted.strip().split()
            print(f"[+] Requested a file upload: {name} with length: {length}b")
            file_data = sock.recv(int(length) + 128)
            with open(f"./{name}", "wb") as f:
                f.write(file_data)
            print(f"[+] File written: ./{name}\n> ")
            continue

        print(f"\r[{address[0]}:{address[1]}]: {decrypted}\n> ", end="")

def send_msgs(con_data : tuple, peer_pub : rsa.PublicKey) -> None:
    """
    This function sends messages to the remote peer\n
    Arguments : tuple(str(remote_ip), int(remote_port)), rsa.PublicKey(peer_pub)\n
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
            # TODO: Implement encryption when sending file
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

        encrypted = rsa.encrypt(message.encode(), peer_pub)
        # assuming message is no longer than 245
        sock.sendto(encrypted, con_data)

if __name__ == "__main__":
    # connecting to rendezvous server to check in on server
    peer_data, peer_pub_key = connect_to_rendezvous()
    # start listener loop
    l_thread = threading.Thread(target=start_listener)
    l_thread.daemon = True
    l_thread.start()
    # Send messages to the remote peer
    send_msgs(peer_data, peer_pub_key)