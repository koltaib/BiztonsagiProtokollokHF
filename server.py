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
    upload_cache = {}

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

        elif(cmd == 'dnl'):
            if len(args) < 1 or not os.path.isfile(args[0]):
                reply = "failed"
            else:
                f = open(args[0], 'rb')
                content = f.read()
                f.close()
        
                file_size = os.stat(path).st_size

                h = SHA256.new()
                h.update(content)
                file_hash = h.hexdigest()


                
        elif(cmd == 'upl'):
            reply = "Upload file..."
        else:
            reply="Ok."

        return reply

    def handle_upl(self, message):
        payload = self.decode_data(message)
        file_name = payload.split(b'\n',1)[0].decode('utf-8')
        payload = payload.split(b'\n',1)[1]
        
        message_type = message[0]
        port = str(self.transport.get_extra_info('peername')[1])
        if port not in self.upload_cache:
            self.upload_cache[port] = []
        self.upload_cache[port].append(payload)

        if message_type == 'uploadReq1':
            content = b''.join(self.upload_cache[port])
            f = open(f'{os.getcwd()}/{file_name}', "wb")
            f.write(content)
            f.close()
            self.upload_cache[port] = []
            h = SHA256.new()
            h.update(content)
            file_hash = h.hexdigest()
            file_length = len(content)
            payload = str(file_hash) + '\n' + str(file_length)

            rnd = np.random.bytes(6)
            sequenceNumber = message[1]
            nonce = sequenceNumber.to_bytes(2,'big') + rnd

            encr_data, authtag, encr_tk = self.encode_payload('uploadRes', payload, nonce)

            info, preparedMessage = CP.prepareMessage(('uploadRes', sequenceNumber, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

            if info != "failed":
                self.transport.write(preparedMessage)
            
        
        return

        
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
                self.handle_upl(message)
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
