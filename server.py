import asyncio
from comprot import ComProt
from encrypt import Encrypter
from rsa_key_gen import ServerRSA
import numpy as np
from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF
import scrypt
import time

import os


host = '127.0.0.1'
port = 5150
CP = ComProt()

SERVER_HOME = os.getcwd()

pubkey_file_path = "priv_key.txt"

class EchoServerProtocol(asyncio.Protocol, Encrypter):
    time_window = 2e9 # 2 seconds in nanosecond, used to check timestamps
    rsakey = 0
    key = 0
    #Connections is a dictionary, storing every userdata, like that:
    #'username' : ("peername", "hashed password", "random salt")
    #------ username: is the login username, it is the key because it doesn't change
    #------ peername: host + port of client, it changes by every active connection
    #------ hashed password: only hashed passwords are stores, and their salt
    #------ random salt: for every password, a random number is generated as salt, stored for authentication

    connections = { 'alice' : (0, 0, 0), 'bob' : (0,0,0), 'charlie' : (0,0,0)}

    def __init__(self):

        #Load stored RSA PRIVATE (!) key
        self.rsakey = ServerRSA.load_keypair(pubkey_file_path)

        #Sign up default users
        self.signup("alice", "aaa")
        self.signup("bob", "bbb")
        self.signup("charlie", "ccc")

    #Password hash method implemented in Server (and not in Encrypter) because we don't want Client to know which hash method we use
    def signup(self, username, password):
        
        #For every password, a random number is generated for salt, and stored with password hash as well
        #lenght of random salt is equal to length of password, but minimum 8
        l = 8 if len(password) < 8 else len(password) 
        random_salt = Random.get_random_bytes(l)

        #Hash password with random salt
        hashed_password = scrypt.hash(password, random_salt)

        #Store random salt and hashed password in connections dictionary
        self.connections[username] = ("", hashed_password, random_salt)
        return
    
    def check_password(self, username, password):

        #Check if user exists
        if self.connections.get(username, 'Not found') == 'Not found':
            return False
        else:
            #Get stored userdata
            userdata = self.connections[username]

            #Get stored salt and hash received password with it
            salt = userdata[2]
            #Hash password with stored salt
            hashed_password = scrypt.hash(password, salt)

            #Compare with stored hashed password
            stored_hashed_password = userdata[1]

            if hashed_password != stored_hashed_password:
                #Password OK
                return False
            else:
                return True

    def check_timestamp(self, timestamp):
        server_timestamp = time.time_ns()
        if server_timestamp - self.time_window/2 < timestamp < server_timestamp + self.time_window/2:
            return True
        else:
            return False


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
        password_success = self.check_password(username, password)
        timestamp_success = self.check_timestamp(int(timestamp)) #timestamp received as string
        if not password_success or not timestamp_success:
            return "failed"

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

        encPayload, mac, etk = self.encode_payload("", payload, nonce)
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

            #Login
            if typ == 'loginReq':
                handle_result = self.handle_login(message)
                #If login failed, close connection
                if handle_result == "failed":
                    print('Close the client socket')
                    self.transport.close()
                return

            #Command
            if typ == 'commandReq':
                reply = self.handle_command(message) #...
                self.transport.write(reply)
                return
            
            #Upload
            if 'uploadReq' in typ:
                self.handle_upl()
                return

            #Download
            if 'dnloadReq' in typ:
                self.handle_dnl()
                return

            
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
