

from inspect import getfile


class ComProt():

    HeaderFields = {

        #-----MTP Protocol--------
        #Version Number-----------
        "versionNumber" : b'\x01\x00',
        #Message Type-------------
        "loginReq" : b'\x00\x00',
        "loginRes" : b'\x00\x10',
        "commandReq": b'\x01\x00',
        "commandRes": b'\x01\x10',
        "uploadReq0": b'\x02\x00',
        "uploadReq1": b'\x02\x01',
        "uploadRes" : b'\x02\x10',
        "dnloadReq" : b'\x03\x00',
        "dnloadRes0": b'\x03\x10',
        "dnloadRes1": b'\x03\x11',
        #Other--------------------
        "rsv" : b'\x00\x00'
        #-------------------------
    }

    def getfield(self, val):
        for key, value in self.HeaderFields.items():
         if val == value:
             return key
        
        print("WARNING: {} value not found in HeaderFields".format(val))
        return ""

    def processMessage(self, message): #process incoming message
        #Checking message length
        ln = message[4:6]
        if len(message).to_bytes(2,'big') != ln:
            print("Lengths don't match: ", ln, len(message))
            print("Message not processed")
            return ("failed","")

        #Gettig version number from message
        versionNum = message[:2]

        #Getting message type, if not in Header Fields (type we don't know), message is not processed
        typ_bytes = message[2:4]
        typ = self.getfield(typ_bytes)
        if typ == "":
            print("Message not processed")
            return("failed", "")
        
        #Getting sequence number, random number and reserved
        sqn = int.from_bytes(message[6:8], "big")
        rnd = int.from_bytes(message[8:10], "big")
        rsv = int.from_bytes(message[10:12], "big")

        #Getting the rest of the message
        #------if it is a login request, rest is enc_payload + mac + etk
        #------otherwise enc_payload + mac
        rest = message[16:]
        etk=b''
        mac=b''
        enc_payload =b''
        if typ == "loginReq":
            etk = rest[-32:]
            mac = rest[-44:-32]
            enc_payload = rest[:-44]
        else:
            mac = rest[-12:]
            enc_payload = rest[:-12]

        #Generating processed message
        #message is an array, each element is an information of the message
        #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
        #------ if not login request, etk is just an empty string
        processedMessage = []
        processedMessage.append(typ)
        processedMessage.append(sqn)
        processedMessage.append(rnd)
        processedMessage.append(enc_payload)
        processedMessage.append(mac)
        processedMessage.append(etk)

        return ("success", processedMessage)
    
    def prepareMessage(self, message): #prepare outgoing message
        
        #message is an array, each element is an information of the message
        #------ message = (typeString, sequenceNumber, rnd, encPayload, mac, etk)
        #------ if not login request, etk is just an empty string
        typ = self.HeaderFields[message[0]]
        sqn = message[1]
        rnd = message[2]
        enc_payload = message[3]
        mac = message[4]
        l = 16 + len(enc_payload) + 12

        if typ == "loginReq":
            etk = message[5]
            l += 32
        
        prepared_message = self.HeaderFields["versionNumber"]
        prepared_message += typ
        prepared_message += l.to_bytes(2, 'big')
        prepared_message += sqn.to_bytes(2,'big')
        prepared_message += rnd.to_bytes(6,'big')
        prepared_message += self.HeaderFields["rsv"]
        prepared_message += enc_payload
        prepared_message += mac

        if typ == "loginReq":
            prepared_message += etk

        return ("success", prepared_message)

    #def __init__():
    #    return
