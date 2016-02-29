import Crypto 					# Import crypto libraries
from Crypto import Random
from Crypto.Cipher import AES 	# Importing AES algorithm
import Tkinter					# Importing tkinter for GUI
from Tkinter import *
import tkFileDialog				# Importing tkFileDialog for GUI
import tkMessageBox				# Importing tkMessageBox for GUI
import hashlib					# Importing libraries for hashing

# Salt size in bytes
SALT_SIZE = 32

# Number of iterations in the key generation
ITERATIONS = 5000

# Generating key when encrypting/decrypting using provided password 
def generate_key(password, salt, ITERATIONS):
	assert ITERATIONS > 0
	key = password + salt

	for i in range(ITERATIONS):
		key = hashlib.sha256(key).digest()

	return key

# Adding "padding" to adjust string block size
def pad_text(text, block_size):
	extra_bytes = len(text) % block_size
	padding_size = block_size - extra_bytes
	padding = chr(padding_size) * padding_size
	padded_text = text + padding

	return padded_text

# Unpadding text
def unpad_text(padded_text):
	padding_size = ord(padded_text[-1])
	text = padded_text[:-padding_size]

	return text

# Generating salt, key and IV before creating cipher. Padding plaintext before encrypting
def encrypt(plaintext, password):
	salt = Crypto.Random.get_random_bytes(SALT_SIZE)
	key = generate_key(password, salt, ITERATIONS)
	initvector = Random.new().read(AES.block_size)
	cipher = AES.new(key, AES.MODE_CBC, initvector)
	padded_plaintext = pad_text(plaintext, AES.block_size)
	ciphertext = cipher.encrypt(padded_plaintext)
	ciphertext_iv = salt + initvector + ciphertext

	return ciphertext_iv

# Salt and IV is pulled from ciphertext. Key and cipher generated before unpadding plaintext
def decrypt(ciphertext, password):
	salt = ciphertext[0:SALT_SIZE]
	ciphertext_no_salt = ciphertext[SALT_SIZE:]
	initvector = ciphertext_no_salt[0:AES.block_size]
	ciphertext_no_iv = ciphertext_no_salt[AES.block_size:]
	key = generate_key(password, salt, ITERATIONS)
	cipher = AES.new(key, AES.MODE_CBC, initvector)
	padded_plaintext = cipher.decrypt(ciphertext_no_iv)
	plaintext = unpad_text(padded_plaintext)

	return plaintext

filename = None

# Encrypt a file
def encrypt_file(filename, key):
	with open(filename, 'rb') as f:
		plaintext = f.read()
	enc = encrypt(plaintext, password)
	with open(filename + ".enc", 'wb') as f:
		f.write(enc)

# Decrypt a file
def decrypt_file(filename, key):
	with open(filename, 'rb') as f:
		ciphertext = f.read()
	dec = decrypt(ciphertext, password)
	with open(filename[:-4], 'wb') as f:
		f.write(dec)

# Load text file
def load_file():
	global key, filename
	text_file = tkFileDialog.askopenfile(filetypes=[('Text Files', 'txt')])
	if text_file.name != None:
		filename = text_file.name

# Adding encryption functionality to GUI
def encrypt_the_file():
	global filename, password
	enc_pass = passg.get()
	if filename != None and enc_pass != "":
		password = enc_pass
		encrypt_file(filename, password)
	else:
		tkMessageBox.showerror(title="Error:", message="There was no file loaded to encrypt")

# Adding decryption functionality to GUI
def decrypt_the_file():
	global filename, password
	dec_pass = passg.get()
	if filename != None and dec_pass != "":
		password = dec_pass
		fname = filename + ".enc"
		decrypt_file(fname, password)
	else:
		tkMessageBox.showerror(title="Error:", message="There was no file loaded, and/or no password to decrypt")

# Adding instruction functionality to GUI (how-to-use instructions for the program)
def show_instruction():
	tkMessageBox.showinfo(title="Program instructions", 
	message="1. Enter password and load selected .txt\n2. When encrypting, a .txt.enc file will be created.\n3. Initial .txt file must be empty before decryption.")

root = Tkinter.Tk()
root.title("PBE+AES")
root.minsize(width=250, height=160)
root.maxsize(width=250, height=160)

show_instructionButton = Tkinter.Button(root, text="Program Instructions", command=show_instruction, width=20)
loadButton = Tkinter.Button(root, text="Load Text File", command=load_file)
encryptButton = Tkinter.Button(root, text="Encrypt File", command=encrypt_the_file, width=15)
decryptButton = Tkinter.Button(root, text="Decrypt File", command=decrypt_the_file, width=15)
passlabel = Label(root, text="Enter Encrypt/Decrypt Password:")
passg = Entry(root, show="*", width=20)

show_instructionButton.pack()
passlabel.pack()
passg.pack()
loadButton.pack()
encryptButton.pack(side=LEFT)
decryptButton.pack(side=RIGHT)


root.mainloop()