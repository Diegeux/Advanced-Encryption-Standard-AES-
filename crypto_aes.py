from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

key = b'@#%105487_963210' #16 bytes
cipher = AES.new(key,AES.MODE_CBC)


inf_senha = input("Informe a senha: ")
csb= str.encode(inf_senha) #CONVERSÃO STR PARA BYTE
print(inf_senha)
print(csb)


ciphertext= cipher.encrypt(pad(csb,AES.block_size))
print(cipher.iv)
print(ciphertext)

with open('cipher_file', 'wb')as c_file:
    c_file.write(cipher.iv)
    c_file.write(ciphertext)
with open('cipher_file', 'rb')as c_file:
    iv = c_file.read(16)    
    ciphertext= c_file.read()

cipher = AES.new(key,AES.MODE_CBC,iv)
plaintext= unpad(cipher.decrypt(ciphertext), AES.block_size)
print(plaintext)
cbs = plaintext.decode('utf-8')
print(cbs)
