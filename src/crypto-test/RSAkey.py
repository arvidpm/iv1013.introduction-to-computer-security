import os
from Crypto.PublicKey import RSA

private = RSA.generate(1024, os.urandom)
public = private.publickey()

print private
print public
private.exportKey()
public.exportKey()