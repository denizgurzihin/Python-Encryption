import random
import hashlib
import os
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from Cryptodome.Cipher import DES

#Question 1_Generating RSA public and private key

# generate private/public key pair
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.algorithms import AES

# generate private/public key pair
KA_minus = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
KA_plus = KA_minus.public_key()

# store the keys in file
KA_minus_pem = KA_minus.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

KA_plus_pem = KA_plus.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

KA_minus_File = open("KA_minus.txt", mode = 'wb')        # open a file in the write mode
KA_minus_File.write(KA_minus_pem)                       # write down the decrypted file
KA_minus_File.close()

KA_plus_File = open("KA_plus.txt", mode = 'wb')        # open a file in the write mode
KA_plus_File.write(KA_plus_pem)                       # write down the decrypted file
KA_plus_File.close()


#QUESTION 2
print("QUESTION 2 : ")

K1_128 = os.urandom(16)                     # generate 128 bit key, 128/8 = 16byte
K2_256 = os.urandom(32)                     # generate 256 bit key, 256/8 = 32byte

print(" Generated 128 bit(16byte) key is : " + str(K1_128))      # print the 128 bit key
print(" Generated 256 bit(32byte) key is : " + str(K2_256))      # print the 256 bit key

# encryption of 128 bit key with public key
Encrypted_K1_128 = KA_plus.encrypt(
    K1_128,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
# encryption of 256 bit key with public key
Encrypted_K2_256 = KA_plus.encrypt(
    K2_256,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("\n Encrypted 128 bit key is : " + str(Encrypted_K1_128))        # printing encrypted 128 bit key
print("\n Encrpyted 256 bit key is : " + str(Encrypted_K2_256))        # printing encrypted 256 bit key

# decrypted the 128 bit key
Decrypted_K1_128 = KA_minus.decrypt(
    Encrypted_K1_128,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# decrypted the 256 bit key
Decrypted_K2_256 = KA_minus.decrypt(
    Encrypted_K2_256,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("")
print(" Decrypted 128 bit key is : " + str(Decrypted_K1_128))       # printing the decrypted 128 bit key
print(" Decrypted 256 bit key is : " + str(Decrypted_K2_256))       # printing the decrypted 256 bit key


#QUESTION3
print("\n\nQUESTION 3 : ")
# Creating Long Text M
Long_Text_M = "\nBu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir.\n" \
              "Bu mesaj kendini tekrar eden bir mesajtır ve 10 kere tekrar edecektir."

Question3_File = open("Question3_File.txt", mode = 'w')        # open a file in the write mode
Question3_File.write(" The Long Message M is : ")
Question3_File.write(Long_Text_M)                               # write down the decrypted file
Question3_File.write("\n\n")


# Hashing the Long Text M
Hash_M = hashlib.sha256(Long_Text_M.encode())
Hex_Hash_M = Hash_M.hexdigest()                         #
Bytes_Hash_M = bytes(str(Hex_Hash_M), 'utf-8')          #

Question3_File.write(" Message Digest H(m) is : \n")
Question3_File.write(Hex_Hash_M)
Question3_File.write("\n\n")

# Encrpyt Hash_M with Private Key
Encrypted_Hash_M = KA_minus.sign(
        Bytes_Hash_M,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Verify The Digital Signature
Decrypted_Hash_M_2 = KA_plus.verify(
            Encrypted_Hash_M,
            Bytes_Hash_M,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
print(" The Long Message M : " + Long_Text_M)
print("\n The H(m) is : " + str(Bytes_Hash_M))
print("\n Digital signature is : " + str(Encrypted_Hash_M))

Question3_File.write(" Digital signature is : \n")
Question3_File.write(str(Encrypted_Hash_M))
Question3_File.write("\n\n")

Question3_File.close()

# QUESTION 4
print("\n\nQUESTION 4")
IV = os.urandom(16)                             # generate 64 bits for IV
IV_new = os.urandom(16)                         # generate 64 bits for new IV part d

#read the file and prepare the plain text
with open("Input.txt", 'r') as f:
    Plain_Text = f.read()
f.close()

while len(Plain_Text) % 16 != 0:                # make the message length as multiplicity of 16 for the cipher blocks
    Plain_Text = Plain_Text + " "

block_number = len(Plain_Text) / 16             # calculate how many block will need for the operation

backend = default_backend()
block_Cipher_AES_128 = Cipher(algorithms.AES(K1_128), modes.CBC(IV), backend=backend)                       # create cipher for AES_128
AES_128_encryptor = block_Cipher_AES_128.encryptor()                                                        # create the encryptor AES_128
AES_128_decryptor = block_Cipher_AES_128.decryptor()                                                        # create the decryptor AES_128

final_Encrypted_AES128_File = b''                      # create initialy empty byte variable to hold the final encrypted file for AES128
###### ENCRYPTION FOR AES128
Time_Start_AES_128 = time.time()                                                    # the time when aes start
for i in range(0, int(block_number)):                                               # for every block of the message
    S = 16 * i                                                                      # first index
    E = 16 * i + 16                                                                 # second index
    block = Plain_Text[S:E]                                                         # take 16 string each times
    block_Byte = bytes(block, 'utf-8')                                              # convert string to byte
    encrypted_block = AES_128_encryptor.update(block_Byte)                          # encrypt 16bytes of block with AES
    final_Encrypted_AES128_File = b"".join([final_Encrypted_AES128_File, encrypted_block])        # add it up for to send just one message

Time_End_AES_128 = time.time()                                                      # the time when aes_128 finished
Total_Time_AES_128 = Time_End_AES_128 - Time_Start_AES_128                          # total time spent for aes_128
print("This amount of time has been spend for AES_128 encryption : "+ str(Total_Time_AES_128))

AES_128_File_Encrypted = open("Encrypted_AES_128.txt", mode = 'w', encoding='utf-8')            # open a new txt file in the write mode
AES_128_File_Encrypted.write(str(final_Encrypted_AES128_File))                                  # write down the encrypted file
AES_128_File_Encrypted.close()                                                                  # close the file

###### DECRYPTION FOR AES128
final_Decrypted_AES128_File = b''
for i in range(0, int(block_number)):
    S = 16 * i                                                                      # first index
    E = 16 * i + 16                                                                 # second index
    block = final_Encrypted_AES128_File[S:E]                                        # take from message the 16 bytes
    decrypted_block = AES_128_decryptor.update(block)                               # decrypt the message with AES
    final_Decrypted_AES128_File = b"".join([final_Decrypted_AES128_File, decrypted_block])  # add it up to the final message

AES_128_File_Decrypted = open("Decrypted_AES_128.txt", mode = 'wb')                 # open a new txt file in the write byte  mode
AES_128_File_Decrypted.write(final_Decrypted_AES128_File)                           # write down the decrypted file
AES_128_File_Decrypted.close()                                                      # close the file

#----------------------------------------------------------------------------------------------------------------------------------------------------------------#

####### ENCRYPTION WITH AES_128 WITH NEW IV VECTOR
block_Cipher_AES_128_New = Cipher(algorithms.AES(K1_128), modes.CBC(IV_new), backend=backend)                   # create cipher for AES_128
AES_128_encryptor_New = block_Cipher_AES_128_New.encryptor()                                                        # create the encryptor AES_128

final_Encrypted_AES128_New_File = b''                      # create initialy empty byte variable to hold the final encrypted file for AES128
###### ENCRYPTION FOR AES128
for i in range(0, int(block_number)):                                               # for every block of the message
    S = 16 * i                                                                      # first index
    E = 16 * i + 16                                                                 # second index
    block = Plain_Text[S:E]                                                         # take 16 string each times
    block_Byte = bytes(block, 'utf-8')                                              # convert string to byte
    encrypted_block = AES_128_encryptor_New.update(block_Byte)                          # encrypt 16bytes of block with AES
    final_Encrypted_AES128_New_File = b"".join([final_Encrypted_AES128_New_File, encrypted_block])        # add it up for to send just one message

AES_128_File_Encrypted_New = open("Encrypted_AES_128_NEW.txt", mode = 'w', encoding='utf-8')                 # open a new txt file in the write byte  mode
AES_128_File_Encrypted_New.write(str(final_Encrypted_AES128_New_File))                           # write down the decrypted file
AES_128_File_Encrypted_New.close()


#----------------------------------------------------------------------------------------------------------------------------------------------------------------#

###### PREPARE ENCRYPTOR FOR AES 256
block_Cipher_AES_256 = Cipher(algorithms.AES(K2_256), modes.CBC(IV), backend=backend)                       # create cipher for AES256
AES_256_encryptor = block_Cipher_AES_256.encryptor()                                                        # create the encryptor AES256
AES_256_decryptor = block_Cipher_AES_256.decryptor()                                                        # create the decryptor AES256

Time_Start_AES_256 = time.time()                                                    # the time when aes start
final_Encrypted_AES256_File = b''                      # create initialy empty byte variable to hold the final encrypted file for AES256
###### ENCRYPTION FOR AES256
for i in range(0, int(block_number)):                                               # for every block of the message
    S = 16 * i                                                                      # first index
    E = 16 * i + 16                                                                 # second index
    block = Plain_Text[S:E]                                                         # take 16 string each times
    block_Byte = bytes(block, 'utf-8')                                              # convert string to byte
    encrypted_block = AES_256_encryptor.update(block_Byte)                          # encrypt 16bytes of block with AES
    final_Encrypted_AES256_File = b"".join([final_Encrypted_AES256_File, encrypted_block])        # add it up for to send just one message

Time_End_AES_256 = time.time()                                                      # the time when aes_128 finished
Total_Time_AES_256 = Time_End_AES_256 - Time_Start_AES_256                          # total time spent for aes_128
print("This amount of time has been spend for AES_256 encryption : "+ str(Total_Time_AES_256))

AES_256_File_Encrypted = open("Encrypted_AES_256.txt", mode = 'w', encoding='utf-8')        # open file in write mode
AES_256_File_Encrypted.write(str(final_Encrypted_AES256_File))                              # write down the encrypted file
AES_256_File_Encrypted.close()                                                              # close the file


###### DECRYPTION FOR AES256
final_Decrypted_AES256_File = b''
for i in range(0, int(block_number)):
    S = 16 * i                                                                      # first index
    E = 16 * i + 16                                                                 # second index
    block = final_Encrypted_AES256_File[S:E]                                        # take from message the 16 bytes
    decrypted_block = AES_256_decryptor.update(block)                               # decrypt the message with AES
    final_Decrypted_AES256_File = b"".join([final_Decrypted_AES256_File, decrypted_block])  # add it up to the final message

AES_256_File_Decrypted = open("Decrypted_AES_256.txt", mode = 'wb')                         # open the file in write byte mode
AES_256_File_Decrypted.write(final_Decrypted_AES256_File)                                   # wite down the decrypted file
AES_256_File_Decrypted.close()                                                              # close the file

#----------------------------------------------------------------------------------------------------------------------------------------------------------------#

###### DES ENCRYPTION

#read the file again and prepare the plain text
with open("Input.txt", 'r') as f:
    Plain_Text = f.read()
f.close()

while len(Plain_Text) % 8 != 0:                # make the message length as multiplicity of 8 for the cipher blocks
    Plain_Text = Plain_Text + " "

block_number_DES = len(Plain_Text) / 8             # calculate how many block will need for the operation

DES_Key = os.urandom(8)                                             # random 8 byte DES key, one of the byte has been ignored so that it becomes 56bit
DES_IV_Key = os.urandom(8)                                          # random IV key
block_Cipher_DES = DES.new(DES_Key, DES.MODE_CBC, DES_IV_Key)       # DES object for encryption

###### ENCRYPTION FOR DES
Time_Start_DES = time.time()                                                    # measure the time when DES start
final_Encrypted_DES_File = b''
for i in range(0, int(block_number_DES)):                                         # for every block of the message
    S = 8 * i                                                                      # first index
    E = 8 * i + 8                                                                 # second index
    block = Plain_Text[S:E]                                                        # take 8 string each times
    block_Byte = bytes(block, 'utf-8')                                              # convert string to byte
    encrypted_block = block_Cipher_DES.encrypt(block_Byte)                          # encrypt 8 bytes of block with DES
    final_Encrypted_DES_File = b"".join([final_Encrypted_DES_File, encrypted_block])        # add it all up

Time_End_DES = time.time()                          # measure the time, DES finished
Time_Spent_DES = Time_End_DES - Time_Start_DES      # calculate how many seconds spend
print("This amount of time has been spend for DES encryption : "+ str(Time_Spent_DES))

DES_File_Encrypted = open("Encrypted_DES.txt", mode = 'w', encoding='utf-8')        # open file in write mode
DES_File_Encrypted.write(str(final_Encrypted_DES_File))                             # write down the encrypted file
DES_File_Encrypted.close()                                                          # close the file


##### DECRYPTION FOR DES
final_Decrypted_DES_File = b''
block_Cipher_DES_Decrypt = DES.new(DES_Key, DES.MODE_CBC, DES_IV_Key)               # new DES object for decrypt
for i in range(0, int(block_number_DES)):                                           # for every block of the file
    S = 8 * i                                                                       # first index
    E = 8 * i + 8                                                                   # second index
    block = final_Encrypted_DES_File[S:E]
    decrypted_block = block_Cipher_DES_Decrypt.decrypt(block)                          # decrypt 8 byte with DES object
    final_Decrypted_DES_File = b"".join([final_Decrypted_DES_File, decrypted_block])        # add it up for to write just one file

DES_File_Decrypted = open("Decrypted_DES.txt", mode = 'wb')        # open a file in the write mode
DES_File_Decrypted.write(final_Decrypted_DES_File)                             # write down the decrypted file
DES_File_Decrypted.close()                                                          # close the file



