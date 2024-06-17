import os
import binascii


secret_key = binascii.hexlify(os.urandom(32)).decode()
jwt_secret_key = binascii.hexlify(os.urandom(32)).decode()

print("SECRET_KEY =", secret_key)
print("JWT_SECRET_KEY =", jwt_secret_key)