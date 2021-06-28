from tkinter import *
from tkinterdnd2 import DND_FILES,TkinterDnD
from tkinter import messagebox
from tkinter import filedialog
from Crypto.Cipher import AES
from PIL import Image

import os
import time

import AES_ECB
import SHA

import RSA as rsa


class UngDung:

   KEY_128=os.urandom(16)
   KEY_192=os.urandom(24)
   KEY_256=os.urandom(32)
   key=None

   filepath=None

   file_path_save=None

   filepath_RSA=None

   filepath_XacThuc=None

   self_privatekey=None
   self_publickey=None

   filepath_GiaiMa=None

   type_AES=None

   type_File=None

   time_128=None
   time_192=None
   time_256=None
   start=None
   end=None

   format='bmp'

   def CONVERT_TUPLE_TO_BYTE(self,t):  #Chuyển tuple -> list -> string -> byte
      t1 = list(t)
      for i in range(len(t1)):
         t1[i] = str(t1[i])
      t2 = '-'.join(t1)
      t3 = t2.encode()
      return t3


   def CONVERT_BYTE_TO_TUPLE(self,t3): #Chuyển byte -> string -> list -> tuple
      t4 = t3.decode()
      t5 = t4.split('-')
      for i in range(len(t5)):
         t5[i] = int(t5[i])
      t6 = tuple(t5)
      return t6


   def pad(self,data):
      return data + b"\x00" * (16 - len(data) % 16)


   def trans_format_RGB(self,data):
      red, green, blue = tuple(map(lambda e: [data[i] for i in range(0, len(data)) if i % 3 == e], [0, 1, 2]))
      pixels = tuple(zip(red, green, blue))
      return pixels


   def aes_ecb_encrypt(self,key, data, mode=AES.MODE_ECB):
      aes = AES.new(key, mode)
      new_data = aes.encrypt(data)
      return new_data


   def aes_ecb_decryt(self,key, data, mode=AES.MODE_ECB):
      aes = AES.new(key, mode)
      data_pt = aes.decrypt(data)
      return data_pt


   def aes_ecb_encrypt_video(self, message, key):
      message = self.pad(message)
      cipher = AES.new(key, AES.MODE_ECB)
      return cipher.encrypt(message)


   def aes_ecb_decryt_video(self, ciphertext, key):
      cipher = AES.new(key, AES.MODE_ECB)
      plaintext = cipher.decrypt(ciphertext)
      return plaintext.rstrip(b"\0")


   def Create_Key_RSA(self):
      x = rsa.DigitalSignature()

      self.self_privatekey=x.privatekey            # x.GenerateKey_Private()
      self.self_publickey=x.publickey              # x.GenerateKey_Public()

      # SAVE PUBLIC KEY --------------------------------------------------------------------------
      file1 = filedialog.asksaveasfile(mode='wb', defaultextension=".pem",title="SAVE PUBLIC KEY")

      if file1 is None:  # asksaveasfile return `None` if dialog closed with "cancel".
         messagebox.showerror("Thông báo","Chưa chọn file để lưu")
      else:
         self.path_file_RSA = file1.name
         file1.close

         # print(self.path_file_RSA)
         filename=self.path_file_RSA
         file = open(filename,'wb')
         file.write(x.publickey.exportKey('PEM'))
         file.close()

      # SAVE PRIVATE KEY --------------------------------------------------------------------------
         file2 = filedialog.asksaveasfile(mode='wb', defaultextension=".pem",title="SAVE PRIVATE KEY")

         if file2 is None:
            messagebox.showerror("Thông báo","Chưa chọn file để lưu")
         else:
            self.path_file_RSA = file2.name
            file2.close

            filename2 = self.path_file_RSA
            file2 = open(filename2, 'wb')
            file2.write(x.privatekey.exportKey('PEM'))
            file2.close()

            messagebox.showinfo("Thông báo","RSA complete !!!")
            btn_XacThuc.config(state="normal")
            btn_GiaiMa.config(state="normal")


   def Choice_File(self):
      self.filepath = filedialog.askopenfilename(title="Select A Text file",defaultextension=".txt",filetypes=[("Text", "*.txt")])

      if self.filepath == "":
         self.type_File = None
         messagebox.showerror("Thông báo","Chưa chọn file")
      else:
         self.type_File=0
         # print(self.type_File)


   def Choice_Picture(self):
      self.filepath = filedialog.askopenfilename(initialdir="/gui/images",defaultextension=".bmp", title="Select A PICTURE",filetypes=[("image", ".bmp"),])

      if self.filepath == "":
         self.type_File = None
         messagebox.showerror("Thông báo","Chưa chọn ảnh")
      else:
         self.type_File=1
         # print(self.type_File)


   def Choice_Video(self):
      self.filepath = filedialog.askopenfilename(title="Select A VIDEO",defaultextension=".mp4",filetypes=[("all video format", ".mp4"),])

      if self.filepath == "":
         self.type_File = None
         messagebox.showerror("Thông báo","Chưa chọn VIDEO")
      else:
         self.type_File=2
         # print(self.type_File)


   def MaHoa(self):
      if self.type_File is None:    #Kiểm tra dữ liệu plaintext
         messagebox.showerror("Thông báo","Chưa chọn file mã hoá")
      elif self.type_File==0:

         data = open(self.filepath, 'r').read()  # Lấy dữ liệu từ self.filepath

         if self.type_AES == 128:
            self.key=self.KEY_128
         elif self.type_AES==192:
            self.key = self.KEY_192
         elif self.type_AES==256:
            self.key=self.KEY_256

         if self.type_AES is None:       #Kiểm tra Khoá
            messagebox.showerror("Thông báo","Chưa chọn MODE AES")
         else:
            file_key = filedialog.asksaveasfile(mode='wb',title='SELECT FILE SAVE KEY_AES',defaultextension=".txt",filetypes=[("Text file", ".txt"), ])

            if file_key == None:
               messagebox.showerror("Thông báo", "Chưa chọn File Lưu Khoá")
            elif file_key!="":
               file_key.close
               filename = file_key.name
               file = open(filename, 'wb')
               file.write(self.key)
               file.close()


               KEY = self.key
               self.start=time.time()

               cipher = AES_ECB.Encrypt(data, KEY)

               out_sha = SHA.SHA_256(cipher)

               digtl_sig = rsa.DigitalSignature()
               if self.self_privatekey is None:
                  messagebox.showerror("Thông báo","KEY RSA không hợp lệ")
               else:
                  chuki = digtl_sig.CreateSignature(out_sha,self.self_privatekey)

                  str_send = cipher + chuki

                  self.end = time.time()
                  file_save = filedialog.asksaveasfile(mode='wb',defaultextension=".txt")
                  if file_save is None:
                     messagebox.showerror("Thông báo","Chưa chọn file để lưu")
                  else:
                     file_save.write(str_send)
                     self.file_path_save=file_save.name
                     file_save.close
                     messagebox.showinfo("Thông báo","Mã hoá hoàn thành")
                     # os.remove(self.filepath)

                     if self.type_AES == 128:
                        self.time_128 = self.end - self.start
                        txb_128time.delete(0, END)
                        txb_128time.insert(END, self.time_128)

                     elif self.type_AES == 192:
                        self.time_192 = self.end - self.start
                        txb_192time.delete(0, END)
                        txb_192time.insert(END, round(self.time_192, 5))

                     elif self.type_AES == 256:
                        self.time_256 = self.end - self.start
                        txb_256time.delete(0, END)
                        txb_256time.insert(END, round(self.time_256, 5))



      elif self.type_File==1:

         if self.type_AES == 128:
            self.key = self.KEY_128
         elif self.type_AES == 192:
            self.key = self.KEY_192
         elif self.type_AES == 256:
            self.key = self.KEY_256

         if self.type_AES is None:  # Kiểm tra Khoá
            messagebox.showerror("Thông báo", "Chưa chọn MODE AES")
         else:
            file_key = filedialog.asksaveasfile(mode='wb', title='SELECT FILE SAVE KEY_AES', defaultextension=".txt",
                                                filetypes=[("Text file", ".txt"), ])

            if file_key == None:
               messagebox.showerror("Thông báo", "Chưa chọn File Lưu Khoá")
            elif file_key != "":
               file_key.close
               filename = file_key.name
               file = open(filename, 'wb')
               file.write(self.key)
               file.close()

               KEY = self.key

            #------------------------------------------------------------------------------------
               im = Image.open(self.filepath)
               self.start = time.time()
               value_vector = im.convert("RGB").tobytes()      # Chuyển image ("RGB") to byte

               imlength = len(value_vector)
               padding = self.pad(value_vector)  # Padding bytes
               data1 = self.aes_ecb_encrypt(self.key, padding)  # Mã hoá bytes, key: bytes
               self.end=time.time()
               cipher = data1[:imlength]  # Bỏ đoạn dữ liệu mở rộng (bytes)

               BYTE_CUOI=self.CONVERT_TUPLE_TO_BYTE(im.size)
               cipher = cipher + BYTE_CUOI
            #------------------------------------------------------------------------------------
               out_sha = SHA.SHA_256(cipher)
               digtl_sig = rsa.DigitalSignature()
               if self.self_privatekey is None:
                  messagebox.showerror("Thông báo", "KEY RSA không hợp lệ")
               else:
                  chuki = digtl_sig.CreateSignature(out_sha, self.self_privatekey)
                  str_send = cipher + chuki

                  file_save = filedialog.asksaveasfile(title='SAVE FILE PICTURE',mode='wb', defaultextension=".TXT")
                  if file_save is None:
                     messagebox.showerror("Thông báo", "Chưa chọn file để lưu")
                  else:
                     file_save.write(str_send)
                     file_save.close
                     # os.remove(self.filepath)

                     if self.type_AES == 128:
                        self.time_128 = self.end - self.start
                        txb_128time.delete(0, END)
                        txb_128time.insert(END, self.time_128)

                     elif self.type_AES == 192:
                        self.time_192 = self.end - self.start
                        txb_192time.delete(0, END)
                        txb_192time.insert(END, round(self.time_192, 5))

                     elif self.type_AES == 256:
                        self.time_256 = self.end - self.start
                        txb_256time.delete(0, END)
                        txb_256time.insert(END, round(self.time_256, 5))
                     messagebox.showinfo("Thông báo", "Mã hoá PICTURE hoàn thành")
      elif self.type_File==2:

         if self.type_AES == 128:
            self.key = self.KEY_128
         elif self.type_AES == 192:
            self.key = self.KEY_192
         elif self.type_AES == 256:
            self.key = self.KEY_256

         if self.type_AES is None:  # Kiểm tra Khoá
            messagebox.showerror("Thông báo", "Chưa chọn MODE AES")
         else:
            file_key = filedialog.asksaveasfile(mode='wb', title='SELECT FILE SAVE KEY_AES', defaultextension=".txt",filetypes=[("Text file", ".txt"), ])
            if file_key == None:
               messagebox.showerror("Thông báo", "Chưa chọn File Lưu Khoá")
            elif file_key != "":
               file_key.close
               filename = file_key.name
               file = open(filename, 'wb')
               file.write(self.key)
               file.close()

               self.start=time.time()
               KEY = self.key
               pt = open(self.filepath, 'rb').read()
               enc = self.aes_ecb_encrypt_video(pt, KEY)
               self.end=time.time()
               out_sha = SHA.SHA_256(enc)
               digtl_sig = rsa.DigitalSignature()
               if self.self_privatekey is None:
                  messagebox.showerror("Thông báo", "KEY RSA không hợp lệ")
               else:
                  chuki = digtl_sig.CreateSignature(out_sha, self.self_privatekey)

                  str_send = enc + chuki

                  filenamesave = self.filepath + ".enc"
                  print(filenamesave)
                  file = open(filenamesave, 'wb').write(str_send)
                  # os.remove(self.filepath)

                  if self.type_AES == 128:
                     self.time_128 = self.end - self.start
                     txb_128time.delete(0, END)
                     txb_128time.insert(END, self.time_128)

                  elif self.type_AES == 192:
                     self.time_192 = self.end - self.start
                     txb_192time.delete(0, END)
                     txb_192time.insert(END, round(self.time_192, 5))

                  elif self.type_AES == 256:
                     self.time_256 = self.end - self.start
                     txb_256time.delete(0, END)
                     txb_256time.insert(END, round(self.time_256, 5))
                  messagebox.showinfo("Thông báo", "Mã hoá VIDEO hoàn thành")


   def XacThuc(self):
      self.filepath_XacThuc = filedialog.askopenfilenames(title='SELECT FILE', filetypes=[("Text file", ".txt"),("Picture file", ".bmp"),("Video file",".enc"),])

      if self.filepath_XacThuc!="":
         TYPEFILE=self.filepath_XacThuc[0][-4:]

      if self.filepath_XacThuc == "":      #Kiểm tra chọn file
         messagebox.showerror("Thông báo","Chưa chọn file")
      elif TYPEFILE ==".txt":
         path_xacthuc=self.filepath_XacThuc[0]
         data = open(path_xacthuc,'rb').read()

         rsa_l = data[-256:]
         ct = data[:-256]
         hash_r = SHA.SHA_256(ct)

         self.filepath_RSA = filedialog.askopenfilenames(title='select',defaultextension=".pem", filetypes=[("Text pem", ".pem"),])

         if self.filepath_RSA == "":                #Kiểm tra chọn file PEM
            messagebox.showerror("Thông báo","Chưa chọn File PEM")
         else:
            path_privatekeyRSA = self.filepath_RSA[0]

            digtl_sig = rsa.DigitalSignature()
            out = digtl_sig.DecryptSignature(path_privatekeyRSA, rsa_l,self.self_publickey)

            check = False
            if hash_r == out:
               check = True
               messagebox.showinfo("Thông báo","Nội dung không bị thay đổi")
            else:
               check = False
               messagebox.showinfo("Thông báo","Nội dung bị thay đổi")
      elif TYPEFILE ==".TXT":
         path_xacthuc = self.filepath_XacThuc[0]
         data = open(path_xacthuc, 'rb').read()

         rsa_l = data[-256:]
         ct = data[:-256]
         hash_r = SHA.SHA_256(ct)

         self.filepath_RSA = filedialog.askopenfilenames(title='select', defaultextension=".pem",
                                                         filetypes=[("File pem", ".pem"), ])

         if self.filepath_RSA == "":  # Kiểm tra chọn file PEM
            messagebox.showerror("Thông báo", "Chưa chọn File PEM")
         else:
            path_privatekeyRSA = self.filepath_RSA[0]

            digtl_sig = rsa.DigitalSignature()
            out = digtl_sig.DecryptSignature(path_privatekeyRSA, rsa_l, self.self_publickey)

            check = False
            if hash_r == out:
               check = True
               messagebox.showinfo("Thông báo", "Nội dung không bị thay đổi")
            else:
               check = False
               messagebox.showinfo("Thông báo", "Nội dung bị thay đổi")
      elif TYPEFILE == ".enc":
         path_xacthuc = self.filepath_XacThuc[0]
         data = open(path_xacthuc, 'rb').read()

         rsa_l = data[-256:]
         ct = data[:-256]
         hash_r = SHA.SHA_256(ct)

         self.filepath_RSA = filedialog.askopenfilenames(title='select', defaultextension=".pem",
                                                         filetypes=[("File pem", ".pem"), ])

         if self.filepath_RSA == "":  # Kiểm tra chọn file PEM
            messagebox.showerror("Thông báo", "Chưa chọn File PEM")
         else:
            path_privatekeyRSA = self.filepath_RSA[0]
            digtl_sig = rsa.DigitalSignature()
            out = digtl_sig.DecryptSignature(path_privatekeyRSA, rsa_l, self.self_publickey)

            check = False
            if hash_r == out:
               check = True
               messagebox.showinfo("Thông báo", "Nội dung không bị thay đổi")
            else:
               check = False
               messagebox.showinfo("Thông báo", "Nội dung bị thay đổi")


   def GiaiMa(self):
      self.filepath_GiaiMa = filedialog.askopenfilenames(title='SELECT FILE GIAI MA', filetypes=[("Text file", ".txt"),("Picture file",".bmp"),("Video file",".enc")])

      if self.filepath_GiaiMa != "":
         TYPEFILE = self.filepath_GiaiMa[0][-4:]

      if self.filepath_GiaiMa is None:
         messagebox.showerror("Thông báo","Chưa chọn File")
      elif TYPEFILE == ".txt":
         path_file_GIAIMA = self.filepath_GiaiMa[0]
         str_input = open(path_file_GIAIMA, 'rb').read()
         ct = str_input[:-256]

         file_key_AES = filedialog.askopenfilenames(title='SELECT FILE KEY_AES',defaultextension=".pem",filetypes=[("Text file", ".txt"),])

         if file_key_AES == "":
            messagebox.showerror("Thông báo", "Chưa File KEY_AES")
         else:
            path_KEY_AES = file_key_AES[0]
            key = open(path_KEY_AES, 'rb').read()
            pt = AES_ECB.Decrypt(ct, key)

            file2 = filedialog.asksaveasfile(mode='w', defaultextension=".txt")

            if file2 is None:
               messagebox.showerror("Thông báo","Chưa chọn file để lưu")
            else:
               path = file2.name
               file2.close

               file2 = open(path, 'w')
               file2.write(pt)
               file2.close()
               messagebox.showinfo("Thông báo","Giải mã thành công")
      elif TYPEFILE == ".TXT":
         path_file_GIAIMA = self.filepath_GiaiMa[0]
         str_input = open(path_file_GIAIMA, 'rb').read()

         ct = str_input[:-256]

         size_im = self.CONVERT_BYTE_TO_TUPLE(ct[-9:])
         ct=ct[:-9]

         file_key_AES = filedialog.askopenfilenames(title='SELECT FILE KEY_AES', defaultextension=".txt",
                                                    filetypes=[("Text file", ".txt"), ])

         if file_key_AES == "":
            messagebox.showerror("Thông báo", "Chưa File KEY_AES")
         else:
            path_KEY_AES = file_key_AES[0]
            key = open(path_KEY_AES, 'rb').read()

            imlength=len(ct)
            padding=self.pad(ct)
            pt = self.aes_ecb_decryt(key,padding)
            pt=pt[:imlength]

            alue_decrypt = self.trans_format_RGB(pt)     # Chuyển bytes -> rgb (red,green,blue)

            im2 = Image.new('RGB', size_im)              # Khai báo Images với mode = RGB,size = size của hình ảnh mã hoá
            im2.putdata(alue_decrypt)                    # Lấy dữ liệu từ rgb

            name=self.filepath_GiaiMa[0][:-4]+"_AES"
            im2.save(name+"."+self.format, self.format)  # lưu ảnh, với mode
            messagebox.showinfo("Thông báo","Giải mã hoàn thành")
      elif TYPEFILE == ".enc":
         path_file_GIAIMA = self.filepath_GiaiMa[0]
         str_input = open(path_file_GIAIMA, 'rb').read()
         ct = str_input[:-256]

         file_key_AES = filedialog.askopenfilenames(title='SELECT FILE KEY_AES', defaultextension=".pem",
                                                    filetypes=[("Text file", ".txt"), ])

         if file_key_AES == "":
            messagebox.showerror("Thông báo", "Chưa File KEY_AES")
         else:

            path_KEY_AES = file_key_AES[0]
            key = open(path_KEY_AES, 'rb').read()
            pt = self.aes_ecb_decryt_video(ct, key)

            file2 = filedialog.asksaveasfile(mode='wb', defaultextension=".mp4")
            if file2 is None:
               messagebox.showerror("Thông báo", "Chưa chọn file để lưu")
            else:
               path = file2.name
               file2.close

               file2 = open(path, 'wb')
               file2.write(pt)
               file2.close()
               messagebox.showinfo("Thông báo", "Giải mã thành công")


#     __ MAIN__

# Create object ----------------------------------------------------------------------------------------------------------------------------------------------------------
UD=UngDung()
root = TkinterDnD.Tk()     # root = Tk()
root.title("TH2L")
root.geometry("1000x550")
root.resizable(0, 0)

# Add Tiêu Đề ----------------------------------------
lbl_Welcome = Label(root, text="ỨNG DỤNG MÃ HOÁ - GIẢI MÃ FILE", font=("Time 14", 23, "bold"), fg='red')
lbl_Welcome.pack()

# Add password ---------------------------------------
lbl_Password = Label(root, text="PASSWORD:", font=("Time 14", 14), fg='blue').place(x=0, y=50)
def CheckPw():
   pw= txb_Password.get()

   if pw == "teamfour123":
      messagebox.showinfo("Thông báo","PASSWORD CORRECT")
      btn_RSA_key.config(state="normal")
      btn_ChonFile.config(state="normal")
      btn_ChonVideo.config(state="normal")
      btn_ChonPicture.config(state="normal")
      btn_MaHoa.config(state="normal")
   else:
      messagebox.showerror("Thông báo","PASSWORD INCORRECT")

global txb_Password
txb_Password = Entry(root, width=40, font=("Time 14,", 14), show="*")
txb_Password.place(x=150, y=50)

#Add Enter --------------------------------
btn_Enter = Button(root, text="ENTER", font=("Time 14", 10), width=11, heigh=1,command = CheckPw)
btn_Enter.place(x=600, y=50)

#Add RSA_KEY --------------------------------
btn_RSA_key = Button(root, text="Create RSA KEY", font=("Time 14", 14), width=20, heigh=1,command=UD.Create_Key_RSA,state="disabled")
btn_RSA_key.place(x=750, y=50)

# Button Chọn File --------------------------------
btn_ChonFile = Button(root, text="Chọn File", font=("Time 14", 14), width=20, heigh=2,command=UD.Choice_File,state="disabled")
btn_ChonFile.place(x=0, y=150)

#Button Chọn hình ảnh --------------------------------
btn_ChonPicture = Button(root, text="Chọn hình ảnh ", font=("Time 14", 14), width=20, heigh=2,command=UD.Choice_Picture,state="disabled")
btn_ChonPicture.place(x=350, y=150)

# Button Chọn Video ----------------------------------
btn_ChonVideo = Button(root, text="Chọn Video", font=("Time 14", 14), width=20, heigh=2,command=UD.Choice_Video,state="disabled")
btn_ChonVideo.place(x=750, y=150)


#CREATE MODE AES --------------------------------------
def sel():
   UD.type_AES=type_Sha.get()

type_Sha = IntVar()
R1 = Radiobutton(root, text="AES 128", font=("Time 14", 14), variable=type_Sha, value=128,command=sel)
R1.place(x=150, y=100)

R2 = Radiobutton(root, text="AES 192", font=("Time 14", 14), variable=type_Sha, value=192,command=sel)
R2.place(x=300, y=100)

R3 = Radiobutton(root, text="AES 256", font=("Time 14", 14), variable=type_Sha, value=256,command=sel)
R3.place(x=450, y=100)


# Button _ XÁC THỰC -------------------------------------
btn_XacThuc = Button(root, text="Xác Thực ", font=("Time 14", 14), width=40, heigh=2,command=UD.XacThuc,state="disabled")
btn_XacThuc.place(x=250, y=250)

#Button _ Mã Hoá ------------------------------------------
btn_MaHoa = Button(root, text="Mã Hoá ", font=("Time 14", 14), width=20, heigh=2,command=UD.MaHoa,state="disabled")
btn_MaHoa.place(x=0, y=250)

# Button _ GIẢI MÃ ------------------------------------------
btn_GiaiMa = Button(root, text="GIẢI MÃ ", font=("Time 14", 14), width=20, heigh=2,command=UD.GiaiMa,state="disabled")
btn_GiaiMa.place(x=750, y=250)


# Button _ RESET TIME ----------------------------------------
def reset_time():
   txb_128time.delete(0, END)
   txb_192time.delete(0, END)
   txb_256time.delete(0, END)
   UD.time_128=None
   UD.time_192=None
   UD.time_256=None

btn_Reset_Time = Button(root, text="RESET TIME", font=("Time 14", 14), width=20, heigh=1,command=reset_time)
btn_Reset_Time.place(x=750, y=500)

#TIME _ SO SÁNH
lbl_128time = Label(root, text="AES 128:", font=("Time 14", 14), fg='blue').place(x=750, y=350)
txb_128time = Entry(root, width=11, font=("Time 14,", 14))
txb_128time.place(x=850, y=350)

lbl_192time = Label(root, text="AES 192:", font=("Time 14", 14), fg='blue').place(x=750, y=400)
txb_192time = Entry(root, width=11, font=("Time 14,", 14))
txb_192time.place(x=850, y=400)

lbl_256time = Label(root, text="AES 256:", font=("Time 14", 14), fg='blue').place(x=750, y=450)
txb_256time = Entry(root, width=11, font=("Time 14,", 14))
txb_256time.place(x=850, y=450)

#LABEL _ DROP FILE
lbl_DropFile = Label(root, text="Drop File:", font=("Time 14", 14,'bold'), fg='RED').place(x=0, y=350)

#LISTBOX _ DROP FILE
def drop_inside_list_box(event):
   listb.delete(0, END)
   listb.insert("end", event.data)

   tenfile = event.data

   if tenfile[0]=='{' and tenfile[-1]=='}':
      tenfile=tenfile[1:-1]

   UD.filepath=tenfile
   if UD.filepath[-4:]!=".txt" and UD.filepath[-4:]!=".mp4" and UD.filepath[-4:]!=".bmp":
      messagebox.showerror("Thông báo","File không hợp lệ")
      UD.filepath=None
   elif UD.filepath[-4:]==".txt":
      UD.type_File=0
      messagebox.showinfo("Thông báo", "File hợp lệ")
   elif UD.filepath[-4:]==".bmp":
      UD.type_File=1
      messagebox.showinfo("Thông báo", "PICTURE hợp lệ")
   elif UD.filepath[-4:]==".mp4":
      UD.type_File=2
      messagebox.showinfo("Thông báo", "VIDEO hợp lệ")

listb=Listbox(root,width = 60,height = 3,font=("Time 14", 14,'bold'),selectmode=SINGLE)
listb.place(x=50,y=400)


listb.drop_target_register(DND_FILES)
listb.dnd_bind("<<Drop>>",drop_inside_list_box)


root.mainloop()
