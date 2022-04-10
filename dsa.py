from ecdsa import SigningKey
sk = SigningKey.generate() # uses NIST192p
print(sk)
vk = sk.verifying_key
print(vk)
msg=b"New Message"
msg2=b"New Message"
signature = sk.sign(msg)
temp=signature
print(signature)
print(temp)
try:
    assert vk.verify(temp, msg2)
except:
    print("Signature not verified")

print("Succesfull")


# from ecdsa import SigningKey, NIST384p
# sk = SigningKey.generate(curve=NIST384p)
# sk_string = sk.to_string()
# print(sk_string)
# sk2 = SigningKey.from_string(sk_string, curve=NIST384p)
# print(sk_string.hex())
# print(sk2.to_string().hex())