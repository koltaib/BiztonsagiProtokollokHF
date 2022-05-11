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

import os
import math

from base64 import b64decode

host =  '10.71.0.43' #'127.0.0.1'
port = 5150
CP = ComProt()
pubkey_file_path = "pubkey.pem"

class EchoClientProtocol(asyncio.Protocol, Encrypter):

    sequence_number = 1
    last_received_sequence_number = 0
    client_random = 0
    #random_number = 0 SHOULD NOT BE USED
    key = 0
    rsakey = 0
    login_hash = ""
    current_file_hash = ""
    current_file_size = 0
    current_request_hash = ""
    dl_requested = False
    requeste_file_name = ""
    requested_file_size = 0
    requested_file_hash = ""
    download_cache = b''
    requested_upload_file = ""
    upload_file_content_cache = b''
    dnl_started = False
    logged_in = False

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.rsakey = ServerRSA.load_publickey(pubkey_file_path)

        self.sequence_number = 1

        self.loop = loop

    #----- In Encrypter class
    #def encode_payload(self, typ, payload, nonce, rnd)

    def login(self):
        print("----- Log in -----")
        username = input("Username: ")
        password = input("Password: ")

        rnd = Random.get_random_bytes(6)
        nonce = self.sequence_number.to_bytes(2, 'big') + rnd

        #Generating payload from input data
        timestamp = time.time_ns()
        client_rnd = Random.get_random_bytes(16).hex()
        payload = str(timestamp) + "\n"
        payload += username + "\n"
        payload += password + "\n"
        payload += client_rnd

        self.client_random = client_rnd

        #Stores hash for later verification
        hash = SHA256.new()
        hash.update(payload.encode("utf-8"))
        self.login_hash = hash.hexdigest()
        #self.random_number = rnd # should not be used elsewhere

        #encode payload
        self.key = Random.get_random_bytes(32)
        l = 16 + len(payload) + 12 + 256
        header = CP.versionNumber + CP.HeaderFields["loginReq"] + l.to_bytes(2, 'big') + self.sequence_number.to_bytes(2, 'big') + rnd + CP.HeaderFields["rsv"]
        encr_data, authtag, encr_tk = self.encode_payload("loginReq", header, payload, nonce)

        info, preparedMessage = CP.prepareMessage(("loginReq", self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))
        if info != "failed":
            #print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
            self.transport.write(preparedMessage)
            self.sequence_number += 1
        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")

        return

    def process_download_input(self, msg):
        rnd = np.random.bytes(6)
        nonce = self.sequence_number.to_bytes(2, 'big') + rnd
        payload = msg

        l = 16 + len(payload) + 12
        header = CP.versionNumber + CP.HeaderFields["dnloadReq"] + l.to_bytes(2, 'big') + self.sequence_number.to_bytes(2, 'big') + rnd + CP.HeaderFields["rsv"]

        encr_data, authtag, encr_tk = self.encode_payload('dnloadReq', header, payload, nonce)
        info, preparedMessage = CP.prepareMessage(('dnloadReq', self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        if info != "failed":
            self.transport.write(preparedMessage)
            self.sequence_number += 1

        return


    def process_upload_input(self, path): # TODO(mark): empty cache stuff
        # upl /home/mark/src/BiztonsagiProtokollokHF/uplfile

        content = self.upload_file_content_cache

        file_size = self.current_file_size

        n_fragments = math.ceil(file_size/1024)

        for i in range(n_fragments):
            req_mode = "uploadReq0"
            if i+1 == n_fragments:
                req_mode = "uploadReq1"

            rnd = np.random.bytes(6)
            nonce = self.sequence_number.to_bytes(2, 'big') + rnd

            #Generating payload from input data

            payload = content[i*1024:(i+1)*1024]

            #Stores hash for later verification

            #encode payload
            l = 16 + len(payload.decode("utf-8")) + 12
            header = CP.versionNumber + CP.HeaderFields[req_mode] + l.to_bytes(2, 'big') + self.sequence_number.to_bytes(2, 'big') + rnd + CP.HeaderFields["rsv"]

            encr_data, authtag, encr_tk = self.encode_payload(req_mode, header, payload, nonce)

            info, preparedMessage = CP.prepareMessage((req_mode, self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

            if info != "failed":
                self.transport.write(preparedMessage)
                self.sequence_number += 1

        return


    def process_command_input(self,typ,command, params):

        #random number and sequence number
        rnd = Random.get_random_bytes(6)
        nonce = self.sequence_number.to_bytes(2, 'big') + rnd

        #Generating payload from command and params
        payload = command #+ "\n"

        #if there are params, append to payload
        if len(params) != 0:
            payload += "\n"
            for param in params:
                payload += param + "\n"
            payload = payload[:-1] #last \n deleted

        h = SHA256.new()
        h.update(payload.encode('utf-8'))
        self.current_request_hash = h.hexdigest()

        #encode payload
        l = 16 + len(payload.encode("utf-8")) + 12
        header = CP.versionNumber + CP.HeaderFields[typ] + l.to_bytes(2, 'big') + self.sequence_number.to_bytes(2, 'big') + rnd + CP.HeaderFields["rsv"]

        encr_data, authtag, encr_tk = self.encode_payload(typ, header, payload, nonce)


        #Prepare message to send in the used protocol
        info, preparedMessage = CP.prepareMessage((typ, self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        #print("Payload: <", payload, ">")
        #print("Request hash: ", self.current_request_hash)
        #print("ENCR data: ", encr_data)
        #print("MAC: ", authtag.hex())
        #print("KEY: ", self.key.hex())
        #print("Header: ", header.hex())

        return (info, preparedMessage)

    def preprocessInput(self,_cmd):
        cmd = _cmd.split(' ')[0]
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
            self.requested_upload_file = _cmd.split(' ')[1]
            if not os.path.isfile(self.requested_upload_file):
                print(f'"{self.requested_upload_file}" is not a file or does not exists!')
                return

            # TODO(mark): don't do this, this is ugly
            f = open(self.requested_upload_file, 'rb')
            self.upload_file_content_cache = f.read()
            f.close()

            file_size = os.stat(self.requested_upload_file).st_size
            self.current_file_size = file_size

            h = SHA256.new()
            h.update(self.upload_file_content_cache)
            self.current_file_hash = h.hexdigest()

            file_size = os.stat(self.requested_upload_file).st_size
            self.current_file_size = file_size

            return "commandReq"
        if(cmd == "dnl"):
            self.requested_file_name = _cmd.split(' ')[1]
            return "commandReq"
        if(cmd == "Ready"):
            return "dnloadReq"
        if(cmd == "Cancel"):
            return "dnloadReq"
        else:
            return "Not found"

    def connection_made(self, transport):
        self.transport = transport

        self.login()



    async def send_message(self, data):

        self.transport.write(data)
        self.sequence_number += 1

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
            self.logged_in = True
            #setting new key from client random and server random
            #print("Client random: ", self.client_random)
            #print("Server random: ", server_rnd)

            #print("Received loginreq: ", received_loginReqHash)
            #print("Stored login req: ", self.login_hash)
            self.key = HKDF(bytes.fromhex(self.client_random) + bytes.fromhex(server_rnd), 32, bytes.fromhex(received_loginReqHash), SHA256, 1) # rquest_hash will be salt
            #print("Key: ", self.key.hex())

            #print("final key: ", self.key)


    def data_received(self, message):
        #If first 2 bytes are not the communication protocol version number, we don't process it, but print it for debug
        if message[:2] != CP.versionNumber:
            print("Received not valid message, message dropped:")


        typ_bytes = message[2:4]
        typ = CP.getfield(typ_bytes)
        if typ == "":
            print("Error: Type field is empty")
        if "dnloadRes" in typ:
            messages = []
            ln = int.from_bytes(message[4:6], 'big')
            first_message = message[:ln]
            if len(first_message) != ln:
                return
            messages.append(first_message)
            more_messages = True

            ln_prev_messages = ln
            while more_messages:
                #If there are more messages

                if len(message[ln_prev_messages:]) != 0:
                    #Getting length of message i
                    ln_i = int.from_bytes(message[ln_prev_messages:][4:6], "big")


                    #Appending next message to messages
                    current_message = message[ln_prev_messages:ln_prev_messages+ln_i]

                    if len(current_message) == ln_i:
                        messages.append(current_message)
                    else:
                        break
                    #Updating length of previous messages
                    ln_prev_messages += ln_i
                    #print("Another message was ", ln_i, " long.")
                else:
                    more_messages = False

            for m in messages:
#                print(m[:16])
                _, processed_msg = CP.processMessage(m)
 #               print(f'{len(processed_msg)}\n{processed_msg}')
                payload = self.decode_data(processed_msg)

                message_type = processed_msg[0]
                self.download_cache += payload
                if message_type == 'dnloadRes1':

                    h = SHA256.new()
                    h.update(self.download_cache)
                    file_hash = h.hexdigest()
                    file_length = str(len(self.download_cache))

                    if self.requested_file_hash != file_hash or str(self.requested_file_size) != file_length:
                        #print("1")
                        self.transport.close()
                    f = open(f'{os.getcwd()}/{self.requested_file_name}', "wb")
                    f.write(self.download_cache)
                    f.close()
                    self.download_cache = b''
            return


        #Check sequence number
        elif not int.from_bytes(message[6:8], "big") > self.last_received_sequence_number:
            print("Received wrong sequence number, message dropped:")

        #processing valid message
        else:
            #process message
            info, processed_message = CP.processMessage(message)
            if info != "failed":

                #Store last received sequence number
                self.last_received_sequence_number = message[1]

                #If Client not logged in, we expect first message to be login response
                if not self.logged_in:

                    if processed_message[0] == 'loginRes':
                        self.handle_login_response(processed_message)

                    #If first message is not a login response, Client closes the connection
                    else:
                        #print("2")
                        self.transport.close()
                        return

                #If Client is logged in
                else:
                    if processed_message[0] == 'commandRes':
                        payload = self.decode_data(processed_message).decode('utf-8')
                        if payload.split('\n')[1] != self.current_request_hash:
                            #print("3")
                            self.transport.close()

                        if payload.split('\n')[0] == 'upl':
                            if payload.split('\n')[2] == 'accept':
                                self.process_upload_input(self.requested_upload_file)

                        if payload.split('\n')[0] == 'dnl':
                            self.dl_requested = True
                            self.requested_file_size = payload.split('\n')[3]
                            self.requested_file_hash = payload.split('\n')[4]

                        #payload = '\n'.join(payload.split('\n')[2:])
                        try:
                            print(b64decode(payload.split('\n')[-1]).decode("utf-8"))
                        except:
                            p = '\n'.join(payload.split('\n')[3:])
                            if p != "success":
                                print(p)

                    elif processed_message[0] == 'uploadRes':
                        payload = self.decode_data(processed_message).decode('utf-8')
                        if self.current_file_hash != payload.split('\n')[0] or str(self.current_file_size) != payload.split('\n')[1]:
                            #print("stored hash: ", self.current_file_hash)
                            #print("got: ", payload.split('\n')[0])
                            #print("3")
                            self.transport.close()
                        else:
                            self.current_file_hash = ''
                            self.current_file_size = 0
                    elif 'dnloadRes' in processed_message[0]:
                        return
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
            #wait for user iput
            data = await ainput("> ")

            if data == "close":
                #print("0")
                client.transport.close()

            #preprocess user input to see if it is a valid input
            command_type = client.preprocessInput(data)

            #if not know, print warning, wait for next input
            if command_type == 'Not found':
                print("Command not valid")

            #valid input
            elif command_type == 'commandReq':

                #user will type input command and params separated with a space
                command_params = data.split(" ")
                command = command_params[0]
                params = []
                #if input command has params, pass that as well
                if len(command_params) > 1:
                    params = command_params[1:]
                    if command == "upl":
                        params = [os.path.basename(params[0]), str(client.current_file_size), client.current_file_hash]

                info, preparedMesage = client.process_command_input(command_type,command,params)
                #print("Prepared Message: ", info)

                await client.send_message(preparedMesage)
            elif command_type == 'uploadReq':
                continue
            elif command_type == 'dnloadReq':
                client.process_download_input(data)


if __name__ == "__main__":

    loop_ = asyncio.new_event_loop()

    client = EchoClientProtocol(loop_)

    coro = loop_.create_connection(lambda: client, host, port)

    loop_.run_until_complete(coro)

    loop_.run_until_complete(monitor_input(client))
