from Crypto import Random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import HKDF

class Encrypter:
    def encode_payload(self, typ, payload, nonce):

        #Encrypting payload
        AES_key = self.key
        AE = AES.new(AES_key, AES.MODE_GCM, nonce=nonce, mac_len=12)
        encr_data, authtag = b'', b''
        if "uploadReq" not in typ and "dnloadRes" not in typ:
            encr_data, authtag = AE.encrypt_and_digest(payload.encode("utf-8"))
        else:
            encr_data, authtag = AE.encrypt_and_digest(payload)
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
    
    def decode_data(self, message):
        #print("Trying to decode: ", message)
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
