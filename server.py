import asyncio
from comprot import ComProt
from encrypt import Encrypter
from rsa_key_gen import ServerRSA
import numpy as np
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF

import os


host = '127.0.0.1'
port = 5150
CP = ComProt()

SERVER_HOME = os.getcwd()

pubkey_file_path = "priv_key.txt"

class EchoServerProtocol(asyncio.Protocol, Encrypter):
    rsakey = 0
    key = 0
    connections = { 'peername' : "..."}

    def __init__(self):
        self.rsakey = ServerRSA.load_keypair(pubkey_file_path)


    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def create_command_reply(self,cmd):  # NOTE(mark): maybe create a utility class for this
        cmd = cmd.split('\n')
        args = cmd[1:]
        cmd = cmd[0]
        if(cmd == 'pwd'):
            reply = os.getcwd()
        elif(cmd == 'lst'):
            reply = '\n'.join(os.listdir())
        elif(cmd == 'chd'):
            if len(args) > 0:
                try:
                    os.chdir(args[0])
                    reply = f'Directory changed to {os.getcwd()}'
                except OSError:
                    reply = "failed"                
            else:
                try:
                    os.chdir(SERVER_HOME)
                    reply = f'Directory changed to {os.getcwd()}'
                except OSError:
                    reply = "failed"
        elif(cmd == 'mkd'):
            if len(args) < 1:
                reply = "failed"
            else:
                try:
                    os.mkdir(args[0])
                    reply = f'"{args[0]}" directory created'
                except OSError:
                    reply = "failed"
            
        elif(cmd == 'del'):
            if len(args) < 1:
                reply = "failed"
            else:
                try:
                    if not os.path.isfile(args[0]) and not os.path.islink(args[0]) and not os.path.isdir(args[0]):
                        reply = "failed"
                    elif os.path.isfile(args[0]) or os.path.islink(args[0]):
                        os.remove(args[0])
                        reply = f'"{args[0]}" file removed'
                    elif os.path.isdir(args[0]):
                        os.rmdir(args[0])
                        reply = f'"{args[0]}" directory removed'
                except OSError:
                    reply = "failed"

        elif(cmd == 'upl'):
            reply = "Upload file..."
        elif(cmd == 'dnl'):
            reply = "Download file..."
        else:
            reply="Ok."

        return reply

    def handle_login(self, message):
        
        payload = self.decode_data(message)
        splits = payload.decode("utf-8").split("\n")
        timestamp = splits[0]
        username = splits[1]
        password = splits[2]
        #client random not retrieved from splits, because it has been processed before and can be found in message[2]
        print("Received this login credentials: ",username, " ", password)

        #TODO: check if timestamp and password are valid

        #Login Response
        client_rnd = message[2]
        rn = np.random.bytes(6)
        server_rnd = int.from_bytes(rn, "big")
        sequenceNumber = message[1]
        nonce = sequenceNumber.to_bytes(2,'big') + rn
        #Generating hashed login request with rnd we got from client
        hash = SHA256.new()
        hash.update(payload)
        request_hash = hash.hexdigest()
        
        payload = request_hash + "\n"
        payload += str(rn.hex())

        encPayload, mac, etk = self.encode_payload("", payload, nonce) #TODO: a server amikor elkódol egy payload-ot akkor a saját randomját használja a nonce-ban?
        #setting new key from client random and server random
        self.key = HKDF(bytes.fromhex(client_rnd.to_bytes(6,'big').hex() + rn.hex()), 32, request_hash.encode("utf-8"), SHA256, 1) # rquest_hash will be salt
        #print("DEV _ final key: ", self.key)
        info, prepared_message = CP.prepareMessage(("loginRes", sequenceNumber, server_rnd, encPayload, mac, etk))

        if info != "failed":
            #print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
            self.transport.write(prepared_message)
        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", prepared_message, "\n---------------------\n")
        
        return

    async def send_message(self, data):

        self.transport.write(data)

        await asyncio.sleep(0.1)
    
    def handle_command(self,message):
        rn = np.random.bytes(6)
        sequenceNumber = message[1]
        nonce = sequenceNumber.to_bytes(2,'big') + rn
        server_rnd = int.from_bytes(rn, "big")
        payload = self.decode_data(message)
        
        hash = SHA256.new()
        hash.update(payload)
        request_hash = hash.hexdigest()

        payload = payload.decode('utf-8')
        reply = str(self.create_command_reply(payload))


        payload = payload.split('\n')[0]
        payload += '\n' + str(request_hash) + "\n" + reply
        encPayload, mac, etk = self.encode_payload("commandRes", payload, nonce)
        info, prepared_message = CP.prepareMessage(("commandRes", sequenceNumber, server_rnd, encPayload, mac, etk))
        return prepared_message

    #----In Encrypter class
    #def decode_data(self, message)

    def data_received(self, data):

        info, message = CP.processMessage(data)
        #message is an array, each element is an information of the message
        #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
        #------ if not login request, etk is just an empty string

        #Check if message could be processed
        if info != "failed":

            

            #Check message type, and handle message accordingly
            typ = message[0]
            if typ == 'loginReq':
                self.handle_login(message)
                return
            if typ == 'commandReq':
                reply = self.handle_command(message) #...
                self.transport.write(reply)
                return
            if 'uploadReq' in typ:
                self.handle_upl()
                return
            if 'dnloadReq' in typ:
                self.handle_dnl()
                return
            else:
                reply = "Je ne sais pas"
                print('Send: {!r}'.format(reply))
                self.transport.write(reply.encode("utf_8"))

                host,port = self.transport.get_extra_info('peername')
                #self.transport.write(host.encode("utf_8"))
                #self.transport.write(str(port).encode("utf_8"))

                #print('Close the client socket')
                #self.transport.close()
        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", message, "\n---------------------\n")
        
        


async def main():
    # Get a reference to the event loop as we plan to use
    # low-level APIs.
    loop = asyncio.get_running_loop()

    server = await loop.create_server(
        lambda: EchoServerProtocol(),
        host, port)

    async with server:
        await server.serve_forever()


asyncio.run(main())
