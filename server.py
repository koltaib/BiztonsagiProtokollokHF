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
import math

host = '127.0.0.1'
port = 5150
CP = ComProt()

SERVER_HOME = os.getcwd() + "/server"

pubkey_file_path = "priv_key.txt"

class EchoServerProtocol(asyncio.Protocol, Encrypter):
    sequence_number = 1
    last_received_sequence_number = 0

    time_window = 2e9
    rsakey = 0
    key = 0

    client_logged_in = False

    upload_cache = {}
    download_cache = {}

    #Connections is a dictionary, storing every userdata, like that:
    #'username' : ("peername", "hashed password", "random salt")
    #------ username: is the login username, it is the key because it doesn't change
    #------ peername: host + port of client, it changes by every active connection
    #------ hashed password: only hashed passwords are stores, and their salt
    #------ random salt: for every password, a random number is generated as salt, stored for authentication

    # TODO(mark): create a user dict, where we store their caches and sqn to defend against replay attacks. This could also solve the problem with repeated logins
    #connections = { 'alice' : (0, 0, 0), 'bob' : (0,0,0), 'charlie' : (0,0,0)}

    user_dictionary = { 'alice' :   { 'peername' : 0, 'hashed password' : 0, 'random salt' : 0, 'last_received_sequence_number': 0, 'logged in' : False },
                        'bob' :     { 'peername' : 0, 'hashed password' : 0, 'random salt' : 0, 'last_received_sequence_number': 0, 'logged in' : False },
                        'charlie' : { 'peername' : 0, 'hashed password' : 0, 'random salt' : 0, 'last_received_sequence_number': 0, 'logged in' : False }}

    #Cached login requests is a dictionary with usernames, that sent login requests
    #in every login handle, Server iterates through this dictionary and deletes those that are older than time_window
    cached_login_reqs = { }

    def __init__(self):
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
        self.user_dictionary[username]["hashed password"] = hashed_password
        self.user_dictionary[username]["random salt"] = random_salt
        return

    def check_password(self, username, password):

        #Check if user exists
        if self.user_dictionary.get(username, 'Not found') == 'Not found':
            print("Unsuccessful login, no such user.")
            return False
        else:
            #Get stored userdata (userdata is a dictionary)
            userdata = self.user_dictionary[username]

            #Get stored salt and hash received password with it
            salt = userdata['random salt']
            #Hash password with stored salt
            hashed_password = scrypt.hash(password, salt)

            #Compare with stored hashed password
            stored_hashed_password = userdata['hashed password']

            if hashed_password != stored_hashed_password:
                #Password Not Ok
                print("Unsuccessful login, bad password.")
                return False
            else:
                #Password OK
                print("User logged in.")
                return True

    def check_timestamp(self, timestamp):
        server_timestamp = time.time_ns()
        if server_timestamp - self.time_window/2 < timestamp < server_timestamp + self.time_window/2:
            return True
        else:
            print("Unsuccessful login, bad timestamp.")
            return False


    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport
    
    def connection_lost(self, exc):
        username = self.get_username()
        self.user_dictionary[username]['logged in'] = False
        print('The client closed the connection')
    
    def error_received(self, exception):
        print("Error occurred:", exception)

    def create_command_reply(self,cmd):  # NOTE(mark): maybe create a utility class for this
        cmd = cmd.split('\n')
        args = cmd[1:]
        cmd = cmd[0]
        if(cmd == 'pwd'):
            print("Got command: pwd")
            reply = os.getcwd()

        elif(cmd == 'lst'):
            print("Got command: lst")
            reply = '\n'.join(os.listdir())

        elif(cmd == 'chd'):
            if len(args) > 0:
                try:
                    #NOTE(Bea): cd .. only allowed to root
                    current_dir = os.getcwd()

                    new_path = os.path.join(current_dir, os.path.realpath(args[0]))
                    if not new_path.startswith(SERVER_HOME):
                        reply = 'failed'
                        print("User tried to go outside root directory.")

                    else:
                        os.chdir(args[0])
                        reply = f'Directory changed to {os.getcwd()}'
                        print("User changed directory to: ", args[0])

                except OSError as exc:
                    reply = "failed"
                    print("OSError: ", exc)

            else:
                try:
                    os.chdir(SERVER_HOME)
                    reply = f'Directory changed to {os.getcwd()}'
                    print("User changed directory to home")

                except OSError as exc:
                    reply = "failed"
                    print("OSError: ", exc)

        elif(cmd == 'mkd'):
            if len(args) < 1:
                reply = "failed"
                print("Got bad command, mkd without params.")

            else:
                try:
                    os.mkdir(args[0])
                    reply = f'"{args[0]}" directory created'
                    print("User created directory: ", args[0])

                except OSError as exc:
                    reply = "failed"
                    print("OSError: ", exc)

        elif(cmd == 'del'):
            if len(args) < 1:
                reply = "failed"
                print("Got bad command, del without params.")

            else:
                try:
                    if not os.path.isfile(args[0]) and not os.path.islink(args[0]) and not os.path.isdir(args[0]):
                        reply = "failed"
                        print("User tried to delete not empty dir.")

                    elif os.path.isfile(args[0]) or os.path.islink(args[0]):
                        os.remove(args[0])
                        reply = f'"{args[0]}" file removed'
                        print("User removed file: ", args[0])

                    elif os.path.isdir(args[0]):
                        os.rmdir(args[0])
                        reply = f'"{args[0]}" directory removed'
                        print("User removed dir: ", args[0])

                except OSError as exc:
                    reply = "failed"
                    print("OSError: ", exc)

        elif(cmd == 'dnl'):
            if len(args) < 1 or not os.path.isfile(args[0]):
                reply = "failed"
                print("Got bad command, dnl without params or no such file.")

            else:
                print("User downloading...")

                f = open(args[0], 'rb')
                content = f.read()
                f.close()
                file_size = os.stat(args[0]).st_size
                h = SHA256.new()
                h.update(content)
                file_hash = h.hexdigest()
                reply = f'{file_size}\n{file_hash}'
                port = str(self.transport.get_extra_info('peername')[1])
                self.download_cache[port] = content

        elif(cmd == 'upl'):
            if int(args[1]) > 10000000:
                reply = 'failed'

            else:
                port = str(self.transport.get_extra_info('peername')[1])
                self.upload_cache[port] = [args[0]]

                reply = "Upload accepted"
        else:
            reply="failed"

        return reply


    def process_download_input(self, port, message):
        # upl /home/mark/src/BiztonsagiProtokollokHF/uplfile

        file_size = len(self.download_cache[port])
        n_fragments = math.ceil(file_size/1024)

        for i in range(n_fragments):
            req_mode = "dnloadRes0"
            if i+1 == n_fragments:
                req_mode = "dnloadRes1"

            rnd = np.random.bytes(6)
            sequenceNumber = self.sequence_number
            nonce = sequenceNumber.to_bytes(2,'big') + rnd
            #Generating payload from input data

            payload = self.download_cache[port][i*1024:(i+1)*1024]

            #Stores hash for later verification

            #encode payload
            l = 16 + len(payload) + 12
            header = CP.versionNumber + CP.HeaderFields[req_mode] + l.to_bytes(2, 'big') + sequenceNumber.to_bytes(2, 'big') + rnd + CP.HeaderFields["rsv"]
            encr_data, authtag, encr_tk = self.encode_payload(req_mode, header, payload, nonce)
            info, preparedMessage = CP.prepareMessage((req_mode, sequenceNumber, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

            if info != "failed":
                self.transport.write(preparedMessage)
                self.sequence_number += 1

        return

    # FIXME(mark): handle these stuff: the case when user types Ready multiple times in a row, the user types Ready before the dnl commandreq
    def handle_dnl(self, message):
        payload = self.decode_data(message).decode('utf-8')
        port = str(self.transport.get_extra_info('peername')[1])
        if payload == 'Cancel':
            self.download_cache[port] = ''
            return
        else:
            self.process_download_input(port, message)
        return


    def handle_upl(self, message):
        payload = self.decode_data(message)
        port = str(self.transport.get_extra_info('peername')[1])
        file_name = self.upload_cache[port][0]

        message_type = message[0]
        self.upload_cache[port].append(payload)

        if message_type == 'uploadReq1':
            content = b''.join(self.upload_cache[port][1:])
            f = open(f'{os.getcwd()}/{file_name}', "wb")
            f.write(content)
            f.close()
            h = SHA256.new()
            h.update(content)
            file_hash = h.hexdigest()
            file_length = len(content)
            payload = str(file_hash) + '\n' + str(file_length)
            self.upload_cache[port] = []
            rnd = np.random.bytes(6)
            sequenceNumber = self.sequence_number
            nonce = sequenceNumber.to_bytes(2,'big') + rnd
            l = 16 + len(payload) + 12
            header = CP.versionNumber + CP.HeaderFields['uploadRes'] + l.to_bytes(2, 'big') + sequenceNumber.to_bytes(2, 'big') + rnd + CP.HeaderFields["rsv"]
            encr_data, authtag, encr_tk = self.encode_payload('uploadRes', header, payload, nonce)

            info, preparedMessage = CP.prepareMessage(('uploadRes', sequenceNumber, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

            if info != "failed":
                self.transport.write(preparedMessage)
                self.sequence_number += 1


        return

    # FIXME(mark): If a user is logged in and closes the connection the user can't log in anymore
    def handle_login(self, message):

        payload = self.decode_data(message)
        splits = payload.decode("utf-8").split("\n")
        timestamp = splits[0]
        username = splits[1]
        password = splits[2]

        #Store last received sequence number
        self.user_dictionary[username]['last_received_sequence_number'] = message[1]

        #client random not retrieved from splits, because it has been processed before and can be found in message[2]
        print("Received this login credentials: ",username, " ", password)

        #Check if timestamp and password are valid
        password_success = self.check_password(username, password)
        timestamp_success = self.check_timestamp(int(timestamp)) #timestamp received as string
        if not password_success or not timestamp_success:
            #Check functions print someting if one of them failes, no need to print here
            return "failed"

        #Successful login
        self.user_dictionary[username]['peername'] = self.transport.get_extra_info('peername')

        #Login Response
        client_rnd = splits[3]
        rn = np.random.bytes(6)
        server_rnd = Random.get_random_bytes(16).hex()#int.from_bytes(rn, "big")

        sequenceNumber = message[1]
        nonce = sequenceNumber.to_bytes(2,'big') + rn
        #Generating hashed login request with rnd we got from client
        hash = SHA256.new()
        hash.update(payload)
        request_hash = hash.hexdigest()

        payload = request_hash + "\n"
        payload += server_rnd
        l = 16 + len(payload) + 12
        header = CP.versionNumber + CP.HeaderFields["loginRes"] + l.to_bytes(2, 'big') + sequenceNumber.to_bytes(2, 'big') + rn + CP.HeaderFields["rsv"]
        #setting new key from client random and server random
        #print("key:", RSAcipher.decrypt(message[5]))

        encPayload, mac, etk = self.encode_payload("loginRes", header, payload, nonce) #TODO: a server amikor elkódol egy payload-ot akkor a saját randomját használja a nonce-ban?
        #print("DEV _ final key: ", self.key)
        self.key = HKDF(bytes.fromhex(client_rnd) + bytes.fromhex(server_rnd), 32, bytes.fromhex(request_hash), SHA256, 1) # rquest_hash will be salt
        info, prepared_message = CP.prepareMessage(("loginRes", sequenceNumber, int.from_bytes(rn, "big"), encPayload, mac, etk))

        if info != "failed":
            #print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
            self.transport.write(prepared_message)
            self.sequence_number += 1
            #NOTE(Bea): default folder for clients is /server folder, not allowed to go outside
            os.chdir(SERVER_HOME)

        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", prepared_message, "\n---------------------\n")

        return

    async def send_message(self, data):

        self.transport.write(data)
        self.sequence_number += 1

        await asyncio.sleep(0.1)

    def handle_command(self,message):
        rn = np.random.bytes(6)
        sequenceNumber = self.sequence_number
        nonce = sequenceNumber.to_bytes(2,'big') + rn
        server_rnd = int.from_bytes(rn, "big")
        payload = self.decode_data(message)

        hash = SHA256.new()
        hash.update(payload)
        request_hash = hash.hexdigest()

        payload = payload.decode('utf-8')
        reply = str(self.create_command_reply(payload))
        if reply != 'failed':
            reply = 'accept\n' + reply
        else:
            reply = 'rejected'

        payload = payload.split('\n')[0]
        payload += '\n' + str(request_hash) + "\n" + reply
        l = 16 + len(payload) + 12
        header = CP.versionNumber + CP.HeaderFields["commandRes"] + l.to_bytes(2, 'big') + self.sequence_number.to_bytes(2, 'big') + rn + CP.HeaderFields["rsv"]
        encPayload, mac, etk = self.encode_payload("commandRes", header, payload, nonce)
        info, prepared_message = CP.prepareMessage(("commandRes", sequenceNumber, server_rnd, encPayload, mac, etk))
        self.sequence_number += 1
        return prepared_message

    #----In Encrypter class
    #def decode_data(self, message)

    #Get user by active peername
    def get_username(self):
        peername = self.transport.get_extra_info('peername')
        for user in self.user_dictionary:
             if self.user_dictionary[user]['peername'] == peername:
                return user
        return "Not active"

    def data_received(self, data):
        #Getting last received sequence number
        peername = self.transport.get_extra_info('peername')
        username = self.get_username(peername)
        if username == "Not active":
            l_sqn = 0
        else:
            l_sqn = self.user_dictionary[username]['last_received_sequence_number']

        #If first 2 bytes are not the communication protocol version number, we don't process it, but print it for debug
        if data[:2] != CP.versionNumber:
            print("Received not valid message, message dropped:")
            print(data)

        #Check sequence number
        elif not int.from_bytes(data[6:8], "big") > l_sqn:
            print("Received wrong sequence number, message dropped:")


        #processing valid message
        else:

            #process data
            info, message = CP.processMessage(data)
            #message is an array, each element is an information of the message
            #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
            #------ if not login request, etk is just an empty string

            #Check if message could be processed
            if info != "failed":
                self.sequence_number += 1

                #Check message type, and handle message accordingly
                typ = message[0]

                #If client is not already logged in, we expects a login request message first
                username = self.get_username()

                if not self.user_dictionary[username]['logged in']:

                    #Login
                    if typ == 'loginReq':

                        #Handle log in, if password or timestamp failed, it returns "failed"
                        handle_result = self.handle_login(message)

                        #If login failed, close connection
                        if handle_result == "failed":
                            print('Close the client socket')
                            self.transport.close()
                            return

                        #Server stores that client is logged in
                        username = self.get_username()
                        self.user_dictionary[username]['logged in'] = True
                        return

                    #If first message is not a login request, Server closes the connection
                    else:
                        print('Close the client socket')
                        self.transport.close()
                        return
                else:

                    #Store last received sequence number
                    peername = self.transport.get_extra_info('peername')
                    username = self.get_username(peername)
                    self.user_dictionary[username]['last_received_sequence_number'] = message[1]

                    #Command
                    if typ == 'commandReq':
                        reply = self.handle_command(message) #...
                        self.transport.write(reply)
                        self.sequence_number += 1
                        return

                    #Upload
                    if 'uploadReq' in typ:
                        self.handle_upl(message)
                        return

                    #Download
                    if 'dnloadReq' in typ:
                        self.handle_dnl(message)
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
