from Crypto.PublicKey import RSA
from name import username
key = RSA.generate(2048)
private_key = key.exportKey()
file_out = open("./keys/private/{}_private.pem".format(username), "wb")
file_out.write(private_key)
file_out.close()

public_key = key.publickey().exportKey()
file_out = open("../CAkeys/public/{}_public.pem".format(username), "wb")
file_out.write(public_key)
file_out.close()

'''genrsa -out rsa_private_key.pem 1024'''
'''rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem'''