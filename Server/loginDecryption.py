# Encryption class for decrypting login info
# 41 lines
from Crypto.Cipher import AES
import base64
import os
import hashlib
import binascii
from Client import loginEncryption
from itertools import zip_longest


class LoginDecoding:
    def __init__(self, username):
        self.login = loginEncryption.LoginEncoding()
        self.login.setUsername(username)
        self.setUsername()
        self.dateTime = self.login.getDateTime()

    def setUsername(self):
        self.username = self.login.getUsername()

    def setHashedPassword(self, hashedPassword):
        self.hashedPassword = hashedPassword

    def setSalt(self, salt):
        self.salt = salt

    def setAttemptedPasswordHash(self, password):
        self.login.setPasswordWithSalt(password, self.salt)
        self.attemptedPasswordHash = self.login.getPassword()

    def getUsername(self):
        return self.username

    def getDateTime(self):
        return self.dateTime

    def getAttemptedPasswordHash(self):
        return self.attemptedPasswordHash

    def setAttemptedPasswordWithSalt(self, password, salt):
        username = self.getUsername()
        usernamePlain = self.loginDecryption(username)
        print(usernamePlain)
        hashedPassword = self.passwordHashing(usernamePlain, password, salt)
        password = str(hashedPassword)
        return password

    def loginDecryption(self, encodedUsername):
        mode = 'utf-8'

        padding = "{"

        blockSize = 16

        padTheText = lambda s: s + (blockSize - len(s) % blockSize) * padding

        decodeAES = lambda c, e: c.decrypt(base64.b64decode(e))

        cipher = AES.new('This is a username secret key12.')

        decodedUsername = decodeAES(cipher, encodedUsername)

        decodedUsername = str(decodedUsername, mode)

        decodedUsername = decodedUsername.rstrip(padding)

        return decodedUsername


    def passwordHashing(self, username, password, saltDB):
        mode = 'utf-8'
        # uses the username as salt
        usernameSalt = str(username)

        # adds to the username to make a more secure salt
        salt = usernameSalt + 'This is CSC 376'

        # salt = str.encode(salt)
        # store randomSalt with user login info - each user has own random salt

        randomSalt = saltDB

        finalSalt = str(randomSalt) + salt
        finalSalt = str.encode(finalSalt)
        self.salt = finalSalt

        iterations = 22000

        password = str.encode(password)

        hex = hashlib.pbkdf2_hmac(hash_name='sha256',
                                  password=password,
                                  salt=finalSalt,
                                  iterations=iterations,
                                  dklen=128)

        hashHex = binascii.hexlify(hex)

        return hashHex

    def checkPassword(self):
        rightPass = self.hashedPassword
        attemptPass = self.attemptedPasswordHash

        if len(rightPass) == 0:
            print('The password from database is empty or null!')

        if len(attemptPass) == 0:
            print('The password entered is empty or null!')

        assert len(rightPass) == len(attemptPass)

        difference = False

        rightPassArray = list(rightPass)
        attemptPassArray = list(attemptPass)

        assert len(rightPassArray) == len(attemptPassArray)

        arrayLength = len(rightPassArray)
        for index in range(arrayLength - 1):
            compare = rightPassArray[index] == attemptPassArray[index]
            difference |= compare

        return difference


b = LoginDecoding("jessicahua95")
b.setHashedPassword("dde917010ec96e174ef6723dd0e80942697bba9025a8830d4e83fc886ca7eb9819209daef9f9cab0123806a22ff1a13ad7e3be1e9b69d40a1c618d79c83ef907d02c4edd9bdcd78bd99a2633b2a59d2f66f72f8a80e0261f4747b136f14a8f6a457283f735aecfaeffe5446c95c3ce524cd8bec913090abbba65068bedef3d23")
b.setSalt(b')\xa2@@l\xf8\x86\xf2\xe5Xv\x81h\xe2\xc4\x02\x0b\x1e\xb7\x8dd\xb2Ta\x13\xd4\xb7\xc1\x08aA\x92jessicahua95This is CSC 376')
b.setAttemptedPasswordHash("hello")