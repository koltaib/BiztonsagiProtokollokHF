import asyncio
from comprot import ComProt
from rsa_key_gen import ServerRSA

from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP

host = '127.0.0.1'
port = 5150
CP = ComProt()
pubkey_file_path = "priv_key.txt"

class EchoServerProtocol(asyncio.Protocol):
    rsakey = 0
    key = 0
    connections = { 'peername' : "..."}

    def __init__(self):
        self.rsakey = ServerRSA.load_keypair(pubkey_file_path)


    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def handle_command(cmd):
        if(cmd == "pwd"):
            reply = "current working directory..."
        if(cmd == "lst"):
            reply = "List content of the current working directory..."
        if(cmd == "chd"):
            reply = "Change directory..."
        if(cmd == "mkd"):
            reply = "Make directory..."
        if(cmd == "del"):
            reply = "Delete file..."
        if(cmd == "upl"):
            reply = "Upload file..."
        if(cmd == "dnl"):
            reply = "Download file..."
        if(cmd == "Heló"):
            reply = "Hellóbelló..."
        if(cmd == "Viszlát"):
            reply = "A viszont látásra kedves Kliens."
        else:
            reply="Ok."

    def handle_login(self, message):
        print("Received this login payload:")
        payload = self.decode_data(message)
        print(payload)

        #TODO: check if timestamp and password are valid
        
        #Login Response
        rnd = message[2]
        #Generating hashed login request with rnd we got from client
        hash = SHA256.new()
        hash.update(payload.encode("utf-8"))
        self.login_hash = hash.hexdigest()
        self.random_number = rnd
    
    def handle_command(self,message):
        payload = self.decode_data(message)
        print("Received this command: ", payload)
        return

    def decode_data(self, message):
        #message is an array, each element is an information of the message
        #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
        #------ if not login request, etk is just an empty string
        typ = message[0]
        sqn = message[1]
        rnd = message[2]
        enc_payload = message[3]
        mac = message[4]
        etk = message[5]

        #In case of login, we do not have a key yet, data is encrypted with rsa
        if typ == "loginReq":
            RSA_cipher = PKCS1_OAEP.new(self.rsakey)
            try:
                aes_key = RSA_cipher.decrypt(etk)
            except Exception as e:
                print("Decryption failed, message not processed: \n {}".format(e))
                return None
            self.key = aes_key
        #Otherwise we use stored key
        else:
            aes_key = self.key
    	
        #Decrypt payload
        nonce = sqn.to_bytes(2,'big') + rnd.to_bytes(6,'big')
        AE = AES.new(aes_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        try:
            payload = AE.decrypt_and_verify(enc_payload, mac)
        except Exception as e:
            print("Decryption failed, message not processed: \n {}".format(e))
            return None

        return payload

    def data_received(self, data):

        info, message = CP.processMessage(data)
        #message is an array, each element is an information of the message
        #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
        #------ if not login request, etk is just an empty string

        #Check if message could be processed
        if info != "failed":

            reply = "Je ne sais pas"

            #Check message type, and handle message accordingly
            typ = message[0]
            if typ == 'loginReq':
                self.handle_login(message)
            if typ == 'commandReq':
                self.handle_command(message) #...
            if 'uploadReq' in typ:
                self.handle_upl()
            if 'dnloadReq' in typ:
                self.handle_dnl()

                

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