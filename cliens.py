import asyncio

from aioconsole import ainput

from comprot import ComProt
from rsa_key_gen import ServerRSA

import time
import numpy as np

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP

host = '127.0.0.1'
port = 5150
CP = ComProt()
pubkey_file_path = "server_pub_key.txt"

class EchoClientProtocol(asyncio.Protocol):

    sequence_number = 0
    random_number = 0
    key = 0
    rsakey = 0
    login_hash = ""

    login = False

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.rsakey = ServerRSA.load_publickey(pubkey_file_path)

        self.loop = loop
    
    def encode_payload(self, typ, payload, nonce, rnd):

        #Encrypting payload
        self.key = Random.get_random_bytes(32)
        AES_key = self.key
        AE = AES.new(AES_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        encr_data, authtag = AE.encrypt_and_digest(payload.encode("utf-8"))
        
        #Encrypt login request with RSA
        encr_tk = "" # defult is an empty string (won't be processed)
        #In case of login, we do not have a key yet, data is encrypted with rsa
        if typ == "loginReq":
            RSAcipher = PKCS1_OAEP.new(self.rsakey)
            encr_tk = RSAcipher.encrypt(self.key)
        #Otherwise we use stored key
        else:
            aes_key = self.key

        return encr_data, authtag, encr_tk

    def login(self):
        print("----- Log in -----")
        username = input("Username: ")
        password = input("Password: ")

        rnd = np.random.bytes(6)
        nonce = self.sequence_number.to_bytes(2, 'big') + rnd
        
        #Generating payload from input data
        timestamp = time.time_ns()
        client_rnd = hex(int.from_bytes(rnd, "big"))
        payload = str(timestamp) + "\n"
        payload += username + "\n"
        payload += password + "\n"
        payload += str(client_rnd)

        #Stores hash for later verification
        hash = SHA256.new()
        hash.update(payload.encode("utf-8"))
        self.login_hash = hash.hexdigest()
        self.random_number = rnd

        #encode payload
        encr_data, authtag, encr_tk = self.encode_payload("loginReq", payload, nonce, rnd)

        info, preparedMessage = CP.prepareMessage(("loginReq", self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        if info != "failed":
            #print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
            self.transport.write(preparedMessage)
        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
        
        return
    
    def process_command_input(self,typ,command, params):

        #random number and sequence number
        rnd = np.random.bytes(6)
        nonce = self.sequence_number.to_bytes(2, 'big') + rnd
        
        #Generating payload from command and params
        payload = command + "\n"
        for param in params:
            payload += param + "\n"
        payload = payload[:-2] #last \n deleted

        #encode payload
        encr_data, authtag, encr_tk = self.encode_payload(typ, payload, nonce, rnd)

        #Prepare message to send in the used protocol
        info, preparedMessage = CP.prepareMessage((typ, self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        return (info, preparedMessage)

    def processInput(self,cmd):
        if(cmd == "pwd"):
            return "commandReq"
        if(cmd == "lst"):
            return "commandReq"
        if(cmd == "chd"):
            return "commandReq"
        if(cmd == "mkd"):
            return "commandReq"
        if(cmd == "del"):
            return "commandReq"
        if(cmd == "upl"):
            return "uploadReq"
        if(cmd == "dnl"):
            return "dnloadReq"
        else:
            return "Not found"

    def connection_made(self, transport):

        self.transport = transport

        self.login()



    async def send_message(self, data):

        self.transport.write(data)

        await asyncio.sleep(0.1)




    def data_received(self, data):

        print('Data received: {!r}'.format(data.decode()))



    def connection_lost(self, exc):

        print('The server closed the connection')

        self.loop.stop()




async def monitor_input(client: EchoClientProtocol):

    while True:
        if client.login:
            data = await ainput("> ")
            command_type = client.processInput(data)

            if command_type == 'Not found':
                print("Command not valid")
            else:
                command_params = data.split(" ")
                command = command_params[0]
                params = command_params[1:]
                info, preparedMesage = client.process_command_input(command_type,command,params)
                #message is an array, each element is an information of the message
                #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
                #------ if not login request, etk is just an empty string

                print("Prepared Message: ", info)
                
                await client.send_message(preparedMesage)

if __name__ == "__main__":

    loop_ = asyncio.new_event_loop()

    client = EchoClientProtocol(loop_)

    coro = loop_.create_connection(lambda: client, host, port)

    loop_.run_until_complete(coro)

    loop_.run_until_complete(monitor_input(client))