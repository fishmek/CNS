from base64 import encode
from tkinter import *
import onetimepad
from pyDes import *
import base64
import hashlib
from Crypto.Cipher import AES, DES3
from Crypto import Random

window = Tk()
window.title("UI Encryption Decryption")
window.geometry("900x900")


def encrypt():
    if clicked.get() == "OTP":
        cipher = onetimepad.encrypt(my_text1.get(
            1.0, END), encryption_key.get())

    elif clicked.get() == "3DES":
        iv = Random.new().read(DES3.block_size)
        cipher_encrypt = DES3.new(encryption_key.get(), DES3.MODE_OFB, iv)
        plaintext = my_text1.get.get((1.0, END))
        cipher = cipher_encrypt.encrypt(plaintext)

    else:
        BLOCK_SIZE = 16
        def pad(s): return s + (BLOCK_SIZE - len(s) %
                                BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

        def unpad(s): return s[:-ord(s[len(s) - 1:])]

        private_key = hashlib.sha256(
            encryption_key.get().encode("utf-8")).digest()
        plain_text = pad(my_text1.get(1.0, END))
        print("After padding:", plain_text)
        iv = Random.new().read(AES.block_size)
        ciphe = AES.new(private_key, AES.MODE_CBC, iv)
        cipher = base64.b64encode(iv + ciphe.encrypt(plain_text))

    my_text3 = Text(window, width=50, height=10, bg="lightgreen")
    my_text3.grid(row=6, column=1, pady=15)
    my_text3.insert(INSERT, cipher)


def decrypt():
    if clicked.get() == "OTP":
        cipher = onetimepad.encrypt(
            my_text1.get(1.0, END), encryption_key.get())
        msg = onetimepad.decrypt(cipher, decryption_key.get())
        print(msg)

    elif clicked.get() == "3DES":
        iv = Random.new().read(DES3.block_size)
        cipher_encrypt = DES3.new(encryption_key.get(), DES3.MODE_OFB, iv)
        plaintext = my_text1.get.get((1.0, END))
        cipher = cipher_encrypt.encrypt(plaintext)

        cipher_decrypt = DES3.new(decryption_key.get(), DES3.MODE_OFB, iv)
        msg = cipher_decrypt.decrypt(cipher)

    else:
        BLOCK_SIZE = 16
        def pad(s): return s + (BLOCK_SIZE - len(s) %
                                BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)

        def unpad(s): return s[:-ord(s[len(s) - 1:])]

        private_key = hashlib.sha256(
            encryption_key.get().encode("utf-8")).digest()
        plain_text = pad(my_text1.get(1.0, END))
        print("After padding:", plain_text)
        iv = Random.new().read(AES.block_size)
        enc_ciphe = AES.new(private_key, AES.MODE_CBC, iv)
        enc_cipher = base64.b64encode(
            iv + enc_ciphe.encrypt(plain_text))

        private_key = hashlib.sha256(
            decryption_key.get().encode("utf-8")).digest()
        cipher_text = base64.b64decode(enc_cipher)
        iv = cipher_text[:16]
        ciphe = AES.new(private_key, AES.MODE_CBC, iv)
        msg = unpad(ciphe.decrypt(cipher_text[16:]))

    my_text4 = Text(window, width=50, height=10, bg="#FF7276")
    my_text4.grid(row=6, column=2, pady=15)
    my_text4.insert(INSERT, msg)


frame = Frame(window)


encryption_label = Label(
    window, text="Message to Encrypt", bg="grey", font="TimesNewRoman")
encryption_label.grid(row=1, column=1)

my_text1 = Text(window, width=50, height=10, bg="lightgrey")
my_text1.grid(row=2, column=1, padx=25)

key_label = Label(window, text="Encryption Key", justify=LEFT, bg="lightgrey")
key_label.grid(row=3, column=1)

encryption_key = StringVar()
my_entry = Entry(window, width=35, show="*", textvariable=encryption_key)
my_entry.grid(row=4, column=1)

decryption_label = Label(
    window, text="Message to Decrypt", justify=RIGHT, bg="grey", font="TimesNewRoman")
decryption_label.grid(row=1, column=2)

my_text2 = Text(window, width=50, height=10, bg="lightgrey")
my_text2.grid(row=2, column=2)

key_label1 = Label(window, text="Decryption Key", justify=LEFT, bg="lightgrey")
key_label1.grid(row=3, column=2)

decryption_key = StringVar()
my_entry1 = Entry(window, width=35, show="*", textvariable=decryption_key)
my_entry1.grid(row=4, column=2)

decryption_button = Button(
    window, text="Choose Algorithm", bg="grey")
decryption_button.grid(row=7, column=1)

clicked = StringVar()
clicked.set("OTP")

choice = OptionMenu(window, clicked, "OTP", "3DES", "AES")
choice.grid(row=8, column=1)

encryption_button = Button(
    window, text="Encrypt", bg="green", command=encrypt)
encryption_button.grid(row=5, column=1, pady=10)

decryption_button = Button(
    window, text="Decrypt", bg="red", command=decrypt)
decryption_button.grid(row=5, column=2, pady=10)

my_text3 = Text(window, width=50, height=10, bg="lightgreen")
my_text3.grid(row=6, column=1, pady=15)


my_text4 = Text(window, width=50, height=10, bg="#FF7276")
my_text4.grid(row=6, column=2, pady=15)


window.mainloop()
