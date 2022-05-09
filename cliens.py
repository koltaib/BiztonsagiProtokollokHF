import asyncio
from http import server

from aioconsole import ainput

from comprot import ComProt
from encrypt import Encrypter
from rsa_key_gen import ServerRSA

import time
import numpy as np

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF

host = '127.0.0.1'
port = 5150
CP = ComProt()
pubkey_file_path = "server_pub_key.txt"

class EchoClientProtocol(asyncio.Protocol, Encrypter):

    sequence_number = 0
    random_number = 0
    key = 0
    rsakey = 0
    login_hash = ""

    login = False

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.rsakey = ServerRSA.load_publickey(pubkey_file_path)

        self.loop = loop

    #----- In Encrypter class
    #def encode_payload(self, typ, payload, nonce, rnd)

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
        self.key = Random.get_random_bytes(32)
        encr_data, authtag, encr_tk = self.encode_payload("loginReq", payload, nonce)

        info, preparedMessage = CP.prepareMessage(("loginReq", self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        if info != "failed":
            #print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
            self.transport.write(preparedMessage)
        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")

        #TODO: next reply should be login response, else connection close
        return

    def process_command_input(self,typ,command, params):

        #random number and sequence number
        rnd = np.random.bytes(6)
        nonce = self.sequence_number.to_bytes(2, 'big') + rnd

        #Generating payload from command and params
        payload = command
        #if there are params, append to payload
        if len(params) != 0:
            payload += "\n"
            for param in params:
                payload += param + "\n"
            payload = payload[:-1] #last \n deleted

        #encode payload
        encr_data, authtag, encr_tk = self.encode_payload(typ, payload, nonce)

        #Prepare message to send in the used protocol
        info, preparedMessage = CP.prepareMessage((typ, self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        return (info, preparedMessage)

    def preprocessInput(self,cmd):
        cmd = cmd.split(' ')[0]
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


    def handle_login_response(self,processed_message):
        payload = self.decode_data(processed_message)
        hash_and_server_rnd = payload.decode("utf-8").split('\n')
        received_loginReqHash = hash_and_server_rnd[0]
        server_rnd = hash_and_server_rnd[1]
        if (self.login_hash != received_loginReqHash):
            print("\n Received and stored login request hash do not match")
            print(self.login_hash)
            print(received_loginReqHash)
            print("Message dropped.")
        else:
            print("Login successful")
            #setting new key from client random and server random
            self.key = HKDF(bytes.fromhex(hex(int.from_bytes(self.random_number, "big"))[2:] + server_rnd), 32, received_loginReqHash.encode("utf-8"), SHA256, 1) # rquest_hash will be salt
            #print("final key: ", self.key)


    def data_received(self, message):

        #If first 2 bytes are not the communication protocol version number, we don't process it, but print it for debug
        if message[:2] != CP.versionNumber:
            print("Received not valid reply:")
            print(message)

        #processing valid message
        else:
            #process message
            info, processed_message = CP.processMessage(message)
            if info != "failed":
                if processed_message[0] == 'loginRes':
                    self.handle_login_response(processed_message)
                elif processed_message[0] == 'commandRes':  # TODO(mark): validate request_hash
                    payload = self.decode_data(processed_message).decode('utf-8')
                    payload = '\n'.join(payload.split('\n')[2:])
                    print(payload)
                else:
                    print("Received this reply:")
                    payload = self.decode_data(processed_message)
                    print(payload)
            #if process failed
            else:
                print("Message dropped")
                print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", processed_message, "\n---------------------\n")

    def connection_lost(self, exc):

        print('The server closed the connection')

        self.loop.stop()




async def monitor_input(client: EchoClientProtocol):

    while True:
        if client.login:

            #wait for user iput
            data = await ainput("> ")

            #preprocess user input to see if it is a valid input
            command_type = client.preprocessInput(data)

            #if not know, print warning, wait for next input
            if command_type == 'Not found':
                print("Command not valid")

            #valid input
            else:

                #user will type input command and params separated with a space
                command_params = data.split(" ")
                command = command_params[0]
                params = []
                #if input command has params, pass that as well
                if len(command_params) > 1:
                    params = command_params[1:]

                info, preparedMesage = client.process_command_input(command_type,command,params)
                #print("Prepared Message: ", info)

                await client.send_message(preparedMesage)

if __name__ == "__main__":

    loop_ = asyncio.new_event_loop()

    client = EchoClientProtocol(loop_)

    coro = loop_.create_connection(lambda: client, host, port)

    loop_.run_until_complete(coro)

    loop_.run_until_complete(monitor_input(client))
