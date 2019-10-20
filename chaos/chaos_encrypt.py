# Added libraries
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


def encrypt(key, filename):
    chunksize = 64*1024
    outputFile = "en" + filename
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV =Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))


# Added the decrypt function 
def decrypt(key, fName):
    fContents = open(fName).read()
    # File read <16 for size> <16 chars for IV> <Rest>
    fSize = fContents[:16]
    IV = fContents[16:32]
    encrypted = fContents[32:]
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    print decryptor.decrypt(encrypted)


def getKey(password):
            hasher = SHA256.new(password.encode('utf-8'))
            return hasher.digest()


# Calling the decrypt function
decrypt(getKey("sahay"), "enim_msg.txt")
