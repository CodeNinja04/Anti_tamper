# from jose import jws
# contract="This is a sample contract if you are agree on this pls sign the doc"
# signed = jws.sign({"contract":contract}, 'secret', algorithm='HS256')
# print(signed)


# verification=jws.verify(signed, 'secret', algorithms=['HS256'])
# print(verification)
from Crypto.Cipher import AES


key = b'Sixteen byte key'
# print(type(key))
cipher = AES.new(key, AES.MODE_EAX)
data=bytes("hemendrasharma",'utf-8')
nonce = cipher.nonce
# print(nonce)
# n = "4Y\x89\x7f\x1dI\x05}\x19\xa3\xf2, \rJ\xe4}"
# print(nonce == bytes(n,"utf-8"))
ciphertext, tag = cipher.encrypt_and_digest(data)
print(str(ciphertext))
# # plaintext = cipher.decrypt(ciphertext)
# # print(plaintext)

cipher1 = AES.new(key, AES.MODE_EAX,nonce)
plaintext = cipher1.decrypt(ciphertext)
# print(plaintext.decode('utf-8'))
