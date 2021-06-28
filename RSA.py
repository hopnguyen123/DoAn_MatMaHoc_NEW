from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP        #Thư viện dùng để mã hoá, giải mã
from Crypto import Random
from tkinter import filedialog

class DigitalSignature:
    # signature là chữ kí cuối cùng là chữ kí
    signature = None
    # key của RSA
    privatekey = None
    publickey = None
    # giá trị sau khi hash
    hash_value = None

    path_file_RSA=None

    def __init__(self):
        rand = Random.new().read
        self.publickey = RSA.generate(2048, rand)  # Số bit khoá, random, publickey: e,n

        # Tạo một public key
        self.privatekey = self.publickey.publickey()

    # Hàm này dùng để tạo key cho RSA
    def GenerateKey_Private(self):
        # Tạo một private key


        file1 = filedialog.asksaveasfile(mode='wb', defaultextension=".pem")  # , name="publickey")
        filetext1 = self.publickey.exportKey('PEM')
        # print(filetext1)
        file1.write(filetext1)
        self.path_file_RSA=file1.name
        file1.close

    def GenerateKey_Public(self):
        # filename = "privatekey.pem"
        filename = "publickey.pem"
        file = open(filename, 'wb')
        file.write(self.privatekey.exportKey('PEM'))
        file.close()
        # file = filedialog.asksaveasfilename()
        # file = filedialog.asksaveasfile(mode='wb', defaultextension=".pem")#,name="publickey")
        # filetext=self.privatekey.exportKey('PEM')
        # file.write(filetext)
        # file.close


        # Lưu lại publickey
        # filename="publickey.pem"
        # filename = "privatekey.pem"
        # file = open(filename, 'wb')
        # file.write(self.publickey.exportKey('PEM'))
        # file.close()


    # Hàm này dùng để tạo chữ ký số (Mã hoá)
    def CreateSignature(self,input,privatekey):#,pri):
        # Sử dụng tiêu chuẩn PKCS1_OAEP để mã hoá
        rsa_encryption_cipher = PKCS1_OAEP.new(privatekey) #self.privatekey
        self.signature = rsa_encryption_cipher.encrypt(input)
        return self.signature

    # Hàm này dùng để convert signature to hash_value (Giải mã)
    def DecryptSignature(self, file_key,chuki,publickey):
        # Lấy dữ liệu từ file_key (nơi chứa key)
        self.publickey = RSA.importKey(open(file_key).read())

        # Sử dụng tiêu chuẩn PKCS1_OAEP để giải mã
        rsa_decryption_cipher = PKCS1_OAEP.new(publickey)#self.publickey)
        # self.hash_value = rsa_decryption_cipher.decrypt(self.signature)
        self.hash_value = rsa_decryption_cipher.decrypt(chuki)
        return self.hash_value

