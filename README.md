# Server-client
Homework for Cryptographic Protocols class. Task description is in "SiFT v1.0 protocol.md".

A server and a client, communicating on MTP protocol, using encryption and authentication specified in "SiFT v1.0 protocol.md" task description.

## Parameters
- Host: In server.py, host should be changed to the IP address where you want to listen to connections. If testing locally, it should be localhost, so your client could connect. If another device will connect, host should be changed to your device's IP address.
- Public key: If you use local client and server (you run both), client uses server_pub_key.txt, but if only client is used and tested with another server, this path ( pubkey_file_path = ... ) should be changed in cliens.py.

## Running locally
Start server.py with ` python3 ./server.py ` in root folder. Now server is listenning to connections. Then start cliens with `python3 ./cliens.py`. Server will log that there is a new connection, and it will log the host and the port as well. On client side, you should see a log-in prompt, you will be asked to write your username and password.
**IMPORTANT**: clients can connect only before one logs in, it is a bug, something to do with asyncio, but we couldn't find why. So connect as many client as you want, then log in.

**Users:**
- alice, password: aaa
- bob, password: bbb
- charlie, password: ccc

For commands, see "SiFT v1.0 protocol.md" file.
