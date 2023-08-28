# python_udp_p2p_chat
Simple peer-to-peer chat written in Python and UDP sockets

## UDP peer-to-peer chat in Pyhton

### Project structure:
- client application to connect to the chat
- server application to start rendezvous server

### Algorithm:
1. Clients (support only 2 clients) connect to the rendezvous server
2. Server exchanges (ip:port pair) with clients (client A get B's ip and port, client B get A's ip and port)
3. Clients connect to each other (destination ip: destination port) that we recieved from rendezvous server
4. Server can be stopped after (destination_ip:destination_port) exchange
5. Clients can chat in peer-to-peer

### Problems:
1. Implement SSL (Secure Socket Layer) encryption and exchangeable keys
2. Implement file transfer via chat commands like: \send "path to file" (DONE)
3. Implement handeling more than 2 connections in simpler words implement chat rooms
4. Implement mechanism with random port selection (DONE)
5. Implement NAT Traversal technique in this case UDP Hole Punching

### Usage:
Run server first
`bash python3 ./server.py`

Run two client applications
`bash python3 ./client.py`
