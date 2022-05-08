import asyncio

from aioconsole import ainput

from comprot import ComProt
import random
import time

host = '127.0.0.1'
port = 5150
CP = ComProt()

class EchoClientProtocol(asyncio.Protocol):

    sequence_number = 0

    def __init__(self, loop: asyncio.AbstractEventLoop):

        self.loop = loop


    def login(self,transport):
        print("----- Log in -----")
        username = input("Username: ")
        password = input("Password: ")

        rnd = random.random()
        #Generating payload from input data
        timestamp = time.time_ns()
        client_rnd = random.random()
        payload = timestamp.encode("utf-8") + "\n"
        payload += username + "\n"
        payload += password + "\n"
        payload += client_rnd

        #TODO: finish AES and RSA encryption!! 
        print("LOGIN NOT FINISHED")

        CP.prepareMessage("loginReq", self.sequence_number, rnd, payload)
        return

    def connection_made(self, transport):

        self.login(transport)

        self.transport = transport



    async def send_tcp(self, data):

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
        
        await client.send_tcp(data)

if __name__ == "__main__":

    loop_ = asyncio.new_event_loop()

    client = EchoClientProtocol(loop_)

    coro = loop_.create_connection(lambda: client, host, port)

    loop_.run_until_complete(coro)

    loop_.run_until_complete(monitor_input(client))