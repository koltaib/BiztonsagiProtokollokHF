import sys, getpass
from Crypto.PublicKey import RSA

pubkeyfile = "server_pub_key.txt"
privkeyfile = "priv_key.txt"

class ServerRSA:
    def save_publickey(pubkey, pubkeyfile):
        with open(pubkeyfile, 'wb') as f:
            f.write(pubkey.export_key(format='PEM'))

    def save_keypair(keypair, privkeyfile):
        with open(privkeyfile, 'wb') as f:
            f.write(keypair.export_key(format='PEM'))

    def load_publickey(pubkeyfile):
        with open(pubkeyfile, 'rb') as f:
            pubkeystr = f.read()
        try:
            return RSA.import_key(pubkeystr)
        except ValueError:
            print('Error: Cannot import public key from file ' + pubkeyfile)
            sys.exit(1)

    def load_keypair(privkeyfile):
        
        with open(privkeyfile, 'rb') as f:
            keypairstr = f.read()
        try:
            return RSA.import_key(keypairstr)
        except ValueError:
            print('Error: Cannot import private key from file ' + privkeyfile)
            sys.exit(1)
    def generate(self):
        keypair = RSA.generate(2048)
        self.save_publickey(keypair.publickey(), pubkeyfile)
        self.save_keypair(keypair, privkeyfile)
