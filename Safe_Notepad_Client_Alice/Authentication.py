import hashlib
import os

from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
import base64
from name import username


def docx_encoder(docx_path):
    with open(docx_path, 'rb') as docx:
        data = docx.read()
        return data


def docx_decoder(docx_path, data):
    with open(docx_path, 'wb') as new_docx:
        new_docx.write(data)


def signature(digest):
    # sign using private key
    pri_key = RSA.import_key(open("keys/private/{}_private.pem".format(username)).read())
    siged_content = pkcs1_15.new(pri_key).sign(digest)
    return siged_content


def verify_signature(signed_digest, verify_digest):
    ca_path = "../CAkeys/public/"
    pub_list = os.listdir(ca_path)
    for pub in pub_list:
        pub_key = RSA.import_key(open(ca_path + pub).read())
        try:
            pkcs1_15.new(pub_key).verify(verify_digest, signed_digest)
            pk_name = pub.split('_')[0]
            return True, pk_name
        except (ValueError, TypeError):
            continue
    return False, None


def hash_concatenate(data):
    # hash + signature = data package
    digest = SHA256.new(data)
    siged_con = signature(digest)
    package = data + siged_con
    size = len(siged_con)
    return package, size


# check user's public key in CA. If it's in CA,then return True or return False instead.
def hash_separate(data, hash_size):
    docx_data = data[:len(data) - hash_size]
    signed_digest = data[len(data) - hash_size:]
    verify_digest = SHA256.new(docx_data)
    is_true, name = verify_signature(signed_digest, verify_digest)
    if is_true:
        return True, docx_data, name
    else:
        return False, None, None


def encrypt(package):
    with open("keys/AES_key.bin", "rb") as key_file:
        key = key_file.read()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce  # nonce = 8*16 bits
    cipher_package, hmac = cipher.encrypt_and_digest(package)  # hmac = 8*16 bits
    return cipher_package + nonce + hmac


def decrypt(cipher_package):
    cp_len = len(cipher_package)
    hmac = cipher_package[cp_len - 16:]
    nonce = cipher_package[cp_len - 32:cp_len - 16]
    cipher_package = cipher_package[:cp_len - 32]
    with open("keys/AES_key.bin", "rb") as key_file:
        key = key_file.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        plaint_package = cipher.decrypt_and_verify(cipher_package, hmac)
        return plaint_package
    except ValueError:
        print("Message authentication failed! Message maybe damaged.")
        return None


if __name__ == '__main__':
    data = docx_encoder("../document.docx")
    pack, sig_size = hash_concatenate(data)
    encrypted_pack = encrypt(pack)
    with open("../encrypted_data.txt", 'w') as ciphertext:
        c_data = base64.b64encode(encrypted_pack).decode()
        ciphertext.write(c_data)

    with open("../encrypted_data.txt", 'r') as ciphertext:
        data = ciphertext.read()
        data = base64.b64decode(data.encode())
    pack_plaint = decrypt(data)
    flag, docx_data = hash_separate(pack_plaint, 256)
    if flag:
        docx_decoder("../new.docx", docx_data)
    else:
        print("Signature is invalid!")








    # with open("./CAkeys/AES_key.bin", 'wb') as f:
    #     f.write(get_random_bytes(16))
