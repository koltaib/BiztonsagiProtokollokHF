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

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.rsakey = ServerRSA.load_publickey(pubkey_file_path)

        self.loop = loop

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

        #Encrypting payload
        self.key = Random.get_random_bytes(32)
        AES_key = self.key
        AE = AES.new(AES_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        encr_data, authtag = AE.encrypt_and_digest(payload.encode("utf-8"))

        #Encrypt login request with RSA
        RSAcipher = PKCS1_OAEP.new(self.rsakey)
        encr_tk = RSAcipher.encrypt(self.key)

        #Stores hash for later verification
        hash = SHA256.new()
        hash.update(payload.encode("utf-8"))
        self.login_hash = hash.hexdigest()
        self.random_number = rnd

        info, preparedMessage = CP.prepareMessage(("loginReq", self.sequence_number, int.from_bytes(rnd, "big"), encr_data, authtag, encr_tk))

        if info != "failed":
            #print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
            self.transport.write(preparedMessage)
        else:
            print("Message dropped")
            print("\n------- dev info ------\nMessage process: ", info, "\nMessage is: ", preparedMessage, "\n---------------------\n")
        
        return

    def connection_made(self, transport):

        self.transport = transport

        self.login()



    async def send_message(self, data):

        self.transport.write(data.encode())

        await asyncio.sleep(0.1)




    def data_received(self, data):

        print('Data received: {!r}'.format(data.decode()))



    def connection_lost(self, exc):

        print('The server closed the connection')

        self.loop.stop()




async def monitor_input(client: EchoClientProtocol):

    while True:

        data = await ainput('What do you want to do? ')
        
        #message is an array, each element is an information of the message
        #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
        #------ if not login request, etk is just an empty string
        preparedMessage = CP.prepareMessage((data, 0, 0, b'\xcc\xcc', b'\xdd\x00\x00\x10\x00\x18\x00\x00\x00\x00\x00\xdd', b''))
        processedMessage = CP.processMessage(preparedMessage[1])
        print("Prepared Message: ", preparedMessage)
        print("Processed Message: ", processedMessage)
        
        await client.send_message(data)

if __name__ == "__main__":

    loop_ = asyncio.new_event_loop()

    client = EchoClientProtocol(loop_)

    coro = loop_.create_connection(lambda: client, host, port)

    loop_.run_until_complete(coro)

    loop_.run_until_complete(monitor_input(client))