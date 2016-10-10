import Tkinter  # Importing tkinter for GUI
import os  # Importing os module for urandom (random bytes suitable for cryptographic use)

import tkFileDialog  # Importing tkFileDialog for GUI
import tkMessageBox  # Importing tkMessageBox for GUI
from Crypto import Random
from Crypto.Cipher import AES  # Importing AES algorithm

password = 'hej123'
iterations = 5000
key = ''
salt = os.urandom(32)

key = PBKDF2(password, salt, dkLen=32, count=iterations)


# Use this line for a 128 bit generated key.
# Warning! Encrypting and restarting the application will generate a new key = unable to decrypt!
# key = os.urandom(AES.block_size)

# Use any of these lines for a static 256 bit key input
# key = b'\x18\xad\x07\x08\xb3?\xfe\xa9\x14\t\xb2\x15\xa4\xf7\x1c>\xdd#\xb6\xb4m\x88\xc1\t5f\x81\x86\xe9}\x94e'
# key = b'\xe8\xca\xfby\xcd4\x18VU\x82\xcb!\xebE\x95\x93\xf5A@$jC\xec{\x16\x1b\xa1c%\xa9\x11W'

# Adding "padding" to adjust string block size
def pad(s):
    return s + b"\0" * (AES.block_size - len(s) % AES.block_size)


# Encrypt string
def encrypt(message, key):
    message = pad(message)  # Padding string
    initvector = Random.new().read(AES.block_size)  # Adding a initialization vector to avoid repetition
    cipher = AES.new(key, AES.MODE_CBC, initvector)  # Create cipher
    return initvector + cipher.encrypt(message)  # Return ciphertext version of string


# Decryptciphertext
def decrypt(ciphertext, key):
    initvector = ciphertext[:AES.block_size]  # Initialization vector from encrypt stage
    cipher = AES.new(key, AES.MODE_CBC, initvector)  # Get a cipher
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])  # Decrypt ciphertext
    return plaintext.rstrip(b"\0")  # Remove string padding, and return plaintext


filename = None


# Encrypt a file
def encrypt_file(filename, key):
    with open(filename, 'rb') as f:  # Open file, read as binary
        plaintext = f.read()  # Store the text
    enc = encrypt(plaintext, key)  # Encrypt the text to variable enc
    with open(filename + ".enc", 'wb') as f:  # Create new file with .enc extension, write binary
        f.write(enc)  # Write ciphertext to .enc file


# Decrypt a file
def decrypt_file(filename, key):
    with open(filename, 'rb') as f:  # Open file, read as binary
        ciphertext = f.read()  # Store the ciphertext
    dec = decrypt(ciphertext, key)  # Decrypt the text to variable dec
    with open(filename[:-4], 'wb') as f:  # Open original text file as binary
        f.write(dec)  # Write plaintext to .txt file


# Adding instruction functionality to GUI (how-to-use instructions for the program)
def show_instruction():
    tkMessageBox.showinfo(title="Program instructions",
                          message="1. Create a .txt file containing the text you wish to encrypt.\n2. Locate and select the .txt file.\n3. When encrypting, a .txt.enc file will be created with the encrypted information.\n4. Before decryption, the initial .txt file must be empty.")


# Adding show-key functionality to GUI
def show_key():
    tkMessageBox.showinfo(title="Show key",
                          message=("Currently using: AES-") + str(len(key * 8)) + ("\nKey: ") + key.encode('hex'))


# Load text file
def load_file():
    global key, filename
    text_file = tkFileDialog.askopenfile(filetypes=[('Text Files', 'txt')])
    if text_file.name != None:
        filename = text_file.name


# Adding encryption functionality to GUI
def encrypt_the_file():
    global filename, key
    if filename != None:
        encrypt_file(filename, key)
    else:
        tkMessageBox.showerror(title="Error:", message="There was no file loaded to encrypt")


# Adding decryption functionality to GUI
def decrypt_the_file():
    global filename, key
    if filename != None:
        fname = filename + ".enc"
        decrypt_file(fname, key)
    else:
        tkMessageBox.showerror(title="Error:", message="There was no file loaded to decrypt")


root = Tkinter.Tk()
root.title("File Encrypt")
root.minsize(width=250, height=230)
root.maxsize(width=250, height=230)

show_instructionButton = Tkinter.Button(root, text="Instructions", command=show_instruction)
show_keyButton = Tkinter.Button(root, text="Show key", command=show_key)
loadButton = Tkinter.Button(root, text="Load Text File", command=load_file)
encryptButton = Tkinter.Button(root, text="Encrypt File", command=encrypt_the_file)
decryptButton = Tkinter.Button(root, text="Decrypt File", command=decrypt_the_file)

show_instructionButton.pack()
show_keyButton.pack()
loadButton.pack()
encryptButton.pack()
decryptButton.pack()

root.mainloop()
