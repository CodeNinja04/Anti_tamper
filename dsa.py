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


