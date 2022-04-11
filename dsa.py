from jose import jws
contract="This is a sample contract if you are agree on this pls sign the doc"
signed = jws.sign({"contract":contract}, 'secret', algorithm='HS256')
print(signed)


verification=jws.verify(signed, 'secret', algorithms=['HS256'])
print(verification)

