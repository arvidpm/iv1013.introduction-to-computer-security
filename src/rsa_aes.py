# -*- coding: cp1252 -*-
#Note that rsa key should be at least 1024 bits long
#this use at the moment 500 bit keys because this isn't the fastest implementation but I'm working on to improve it :)
#the program uses different keys and ivs for sending and receiving, which isn't necessary
#and it uses the default 128bit AES but it can be changed
#At the moment the keyboard reading is blocking so you can't receive message while you have started to type

#This program is made for Windows but you can easily change to be Linux compatible by making a new keyboard read 
#The example is made by: Anssi Salo (www.intelligentprogramming.com)

import select
import socket
import sys
import msvcrt #only for windows to make the keyboard read
from Crypto.Cipher import AES #www.pycrypto.org
from Crypto.Hash import SHA256
import Crypto.Util.number
import Crypto.Util.randpool

#source http://www.programmish.com/?p=34:
def modpow(base, exponent, modulus): #calculate modulus and power at the same time, more efficient than calculating them serately
    result=1
    while exponent > 0:
            if exponent & 1 == 1:
                    result = (result* base) % modulus
            exponent = exponent >> 1
            base = (base * base) % modulus
    return result

def gen_prime(bits): #get a prime number
    swimmingpool = Crypto.Util.randpool.RandomPool()
    return (Crypto.Util.number.getPrime(bits,swimmingpool.getBytes))

def gcd (l1, l2): #greatest common divisor
  if l2 == 0: return l1
  else: return gcd(l2, l1 % l2)

def inversed(num, modn):  #inverse modulo        
    x=0 
    y=1
    last_x = 1
    last_y = 0
    b=modn
    a=num

    while b != 0:

           old_b = b #save old b
           division = a / b #division
           b = a % b #how many times fits
           a = old_b #b is the new a

           old_x = x
           x = last_x - division*x #how much left
           last_x = old_x

           old_y = y
           y = last_y - division*y #how much left
           last_y = old_y
                
    return (num+last_y) #original+last y

      
def RSA(prime_size): #generate RSA private and public keys
    p=gen_prime(prime_size) 
    q=gen_prime(prime_size)
    while p==q: #p and q cant be the same
       q=gen_prime(prime_size) 
    
    n=p*q
    phi = (p-1)*(q-1)

    while 1:
        while 1:
           e=gen_prime(prime_size+8) #e must be greater than generated prime :), not so neat way to do this.
           if (e > 1 and e < phi): break #e must be between 1 and phi, too small e leads to breaking the encryption
        while 1: 
            if gcd(phi, e) == 1: break #is a prime
            else: e = e + 2 #check if next number is prime
        d=inversed(phi, e) 
        if (d > 1 and d < phi): break #d must be between 1 and phi

    return ((n,e),(n,d)) #return modulo, (private and public key)

def aes_encode(aes_obj, inputstring): #encrypt aes
    enc_data = aes_obj.encrypt(inputstring)
    data_len = len(enc_data)
    return (data_len, enc_data)

def aes_decode(aes_obj,inputstring): #decrypt aes
    dec_data = aes_obj.decrypt(inputstring)
    return (dec_data)

def sha256_hash(inputstr): #generate hash so the data can't be tempered
    #padding
    pad = len(inputstr)
    padding = pad % 32
    padding = 32 - padding
    if (padding != 32):
        inputstr = inputstr.ljust(pad+padding)    
    sha_obj = SHA256.new(inputstr)
    sha256_string = sha_obj.digest()
    return (sha256_string)

def sha256_hash_hex(inputstr): #send hash as an ascii hex string
    #padding
    pad = len(inputstr)
    padding = pad % 32
    padding = 32 - padding
    if (padding != 32):
        inputstr = inputstr.ljust(pad+padding)    
    sha_obj = SHA256.new(inputstr)
    sha256_string = sha_obj.hexdigest()
    return (sha256_string)

def signature_to_int(input_hex_digest): 
    return int(input_hex_digest, 16) #output

def parse_message(astr,start,moretoparse): 
    posi = astr.find('Z',start,len(astr))#parse message, (messagelen)Z(the actual message)
    if (posi == -1):
        getmoar=start
        moretoparse=-1
        parsed_message=astr
    else:
        msg_len = long(astr[start:posi]) #have to do this because sometimes in the tcp buffer there might more data than the set blocksize
       
        bytes_left = msg_len - (len(astr)-(posi+1))
        if (bytes_left > 0): #part of the message still not received
            getmoar=start #position stays the same
            moretoparse=-1 
            parsed_message=astr
        elif (bytes_left < 0): #there is more than one part in the message
            getmoar=len(astr[start:posi+1+msg_len])
            moretoparse=1
            getmoar=getmoar+start #end of part
            parsed_message=astr[(posi+1):(posi+1)+msg_len] 
        else:
            getmoar=0 #no more message left
            moretoparse=-2
            parsed_message=astr[(posi+1):(posi+1)+msg_len]
    return (moretoparse, getmoar, parsed_message)

def make_a_message(astr):
    string_to_send = str(len(astr))+'Z'+astr #Z is the separator
    return (string_to_send)

def generate_random(bits, n):
    while 1: #generate random secret number
        pool_of_sharks = Crypto.Util.randpool.RandomPool() #in order to make the algorithm actually secure this should not be pseudo random
        #http://www.dlitz.net/software/pycrypto/apidoc/Crypto.Util.randpool.RandomPool-class.html
        #http://www.dlitz.net/software/pycrypto/apidoc/
        #there is some instructions how you can use /dev/urandom in linux

        #http://www.dlitz.net/software/pycrypto/apidoc/
        #^ as stated in link above you can you use Keyboard as Random pool, or get data from mouse
        number=Crypto.Util.number.getRandomNumber(bits,pool_of_sharks.getBytes)
        if (number < n-1 ): break
    return number

def do_things(connected, i,incomming, aes_obj_enc, aes_obj_dec, message_recv,number, n, d, other_pub_n, other_pub_e, challenge):
                          
                            if (message_recv==1): #ugly state machine :)
                                    other_pub_n = long(incomming) #get the other participant's modulus
                                    message_recv += 1
                            elif (message_recv==2): #next state
                                    other_pub_e = long(incomming) #get the other participant's exponent
                                    message_recv += 1
                                    out_num = modpow(number, other_pub_e, other_pub_n) #calculate public key
                                    i.send(make_a_message(str(out_num))) #using public key to encrypt secret number
                            elif (message_recv==3):
                                    key_string = incomming#secret number which used for encryption
                                    a_key = modpow(long(key_string), d, n) #calculate the secret number                            
                                    key_and_iv=sha256_hash(str(a_key)) #generate key and iv, generate hash from the number to be used as initialization 
                                    aes_key=key_and_iv[0:16] #first part is used as key for aes
                                    aes_iv=key_and_iv[16:32] #last is used as initialization vector
                                    aes_obj_enc = AES.new(aes_key, AES.MODE_CBC,aes_iv)
                
                                    message_recv += 1
                                    challenge = generate_random(500, n) #generate challenge to make sure the connection is established ok,
                                    out_num = modpow(challenge, other_pub_e, other_pub_n) #encrypt the challenge
                                    i.send(make_a_message(str(out_num)))
                            elif (message_recv == 4): #receiving the challenge                                     
                                     #answer to challenge
                                     ch = modpow(long(incomming), d, n)
                                     #send back the number
                                     ch = modpow(ch, other_pub_e, other_pub_n) #send back the challenge received and encrypt it
                                     i.send(make_a_message(str(ch)))
                                     message_recv += 1

                            elif (message_recv == 5): #receiving the answer
                                     ch = modpow(long(incomming),d,n) #if the challenge sent is the same as receive everything is ok :)
                                     message_recv+=1
                                     if (str(ch) != str(challenge)):
                                                  print 'Challenge failed'
                                                  chatserv.close()
                                                  exit(1)
                                     else:
                                          print 'Connection established.'
                                          connected=1
                                    
                                                  
                            else:
                                    position_x = incomming.find('X') #(rsa sig)X(message)
                                    data=incomming[position_x+1:]
                                

                                    plain_text = aes_decode(aes_obj_dec, data) #private key for decryption

                                    rsa_val = incomming[0:position_x] #rsa-encoded hash
                                    

                                    hash_val = modpow(long(rsa_val), d, n) #decrypt hash
                                    rsa_val = hash_val #plain num that is generated from hash

                                    the_hash = sha256_hash_hex(plain_text) #generate the hash from message
                                    the_hash = signature_to_int(the_hash) #convert the hash to number

                                    if(rsa_val == the_hash): #is received signature same as the value generated from text
                                        print 'Friend:', plain_text #print data to screen
                                    else:
                                        print 'received a message with invalid hash/signature'#someone else tempered the message

                            return(connected, i,incomming, aes_obj_enc, aes_obj_dec, message_recv,number, n, d, other_pub_n, other_pub_e, challenge)



    
print 'Starting chat...'

count=0
for arg in sys.argv: #get address and port from commandline, server/client
        count += 1
        if count == 2:
            hostaddress = arg
        elif count == 3:
            port = int(arg)
        elif count == 4:
            svr_cl = arg


if (count != 4):
    print '[hostname] [port] [client/server]', count
    sys.exit(1)
    
if svr_cl == 'server':
    server_or_client = 0
elif svr_cl == 'client':
    server_or_client = 1
else:
    print 'enter server or client param. missing'
    sys.exit(1)
    
#hostaddress = '127.0.0.1'
#port = 19996
connections = 1 #num of connections

#server_or_client = 0 #0 for server and 1 for client
blocksize=2048 #try to read 2048 bytes at a time from a socket

(pub, priva) = RSA(512) #generate rsa
n,d=priva #privatekey
n,e=pub #publickey

number = generate_random(500, n) #500bit random, if you change change the other values as well

#print "secret num: ", number
pubkey = modpow(number, e, n)
#print "public:", pubkey
deci = modpow(pubkey,d,n)
#print "decrypt: ",deci


chatserv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #initialize socket

if server_or_client == 0:
        chatserv.bind((hostaddress, port)) #listen for a connection
        chatserv.listen(connections)
        print 'waiting for connections'
        
else:
        #connect to host and port
        chatserv.connect((hostaddress,port))
        chatserv.send(make_a_message(str(n))) #public key n
        chatserv.send(make_a_message(str(e))) #public key e       
                            


inputfrom = [chatserv]
loopforever=1

key_for_sending=sha256_hash(str(number)) #generate key and initilization vector for sending
aes_key_sending=key_for_sending[0:16] #the program uses different keys and to send and receive but it is not necessary
aes_iv_sending=key_for_sending[16:32]
aes_obj_dec = AES.new(aes_key_sending, AES.MODE_CBC,aes_iv_sending) #initialize aes object
other_pub_n = 0
other_pub_e = 0
aes_obj_enc = 0
challenge = ''
message_recv=1
connected=0
while loopforever:

    read_ready, write_ready, error_ready = select.select(inputfrom,[],[],0.1) #0.1 is timeout

    if ((read_ready == [])):    
                if (msvcrt.kbhit() == True):         
                    keyb = raw_input() #blocking read, because of this you can't receive messages while you type, should change this in the future :)
                    print 'Me:',keyb
                    if (keyb == '/quit'): #quit
                        chatserv.close()
                        exit(0)
                    else:                      
                        if(connected == 1):
                            cbc_pad = len(keyb)
                            padding = cbc_pad % 16
                            padding = 16 - padding
                            if (padding != 16):
                                keyb = keyb.ljust(cbc_pad+padding) #add padding if needed

                            hash_value=sha256_hash_hex(keyb)
                            rsa_num = signature_to_int(hash_value)

                            enc_rsa = modpow(rsa_num,other_pub_e, other_pub_n)#signature
 


                            len_of_data, ciphered = aes_encode(aes_obj_enc, keyb) #using publickey for encryption
                            cip_data = str(enc_rsa)+'X'+ciphered #rsa signature X ciphered text, X is used as a separator
                            
                            if server_or_client == 0: #if server
                                i.send(make_a_message(cip_data)) #make our message
                            else: #if client
                                chatserv.send(make_a_message(cip_data)) #make and send
 
    else:
        for i in read_ready:

                if server_or_client ==0: #server
                    if (i==chatserv):
                        if(connected != 1):
                            client_num, client_address = chatserv.accept()
                            inputfrom.append(client_num)
                            print 'a client connected'
                            client_num.send(make_a_message(str(n))) #publickey n
                            client_num.send(make_a_message(str(e))) #publickey e
                        else:
                            client_num, client_address = chatserv.accept()
                            client_num.close()

                    

                    else:
                        str_start_pos=0 #message start position
                        original_in='' #the original message we received
                        moretoparse=-1 #init val, assume there is more than one part in the message
                        while (moretoparse!=-2):
                            if (moretoparse == -1): #-1 missing part of the message
                                incomming = i.recv(blocksize)
                                original_in=original_in + incomming
                                if len(incomming) == 0:
                                    connected = 0
                                    print 'the client disconnected'
                                    inputfrom.remove(i)
                                    message_recv=1
                                    moretoparse=-2
                                    aes_obj_dec = AES.new(aes_key_sending, AES.MODE_CBC,aes_iv_sending)
                                    continue

                                moretoparse, str_start_pos, msg = parse_message(original_in, str_start_pos,moretoparse) 
                            else:
                                moretoparse, str_start_pos, msg = parse_message(original_in, str_start_pos,moretoparse)


                            if (moretoparse != -1):
                                (connected, i,msg, aes_obj_enc, aes_obj_dec, message_recv,number, n, d, other_pub_n, other_pub_e, challenge) = do_things(connected, i,msg, aes_obj_enc, aes_obj_dec, message_recv,number, n, d, other_pub_n, other_pub_e, challenge)                                
                            
                else: #client
                        str_start_pos=0
                        original_in=''
                        moretoparse=-1#init val, assume there is more than one part in the message
                        while (moretoparse!=-2):#-2 no more message left
                            if (moretoparse == -1): ##-1 missing part of the message                                
                                incomming = i.recv(blocksize)
                                original_in=original_in + incomming
                                if len(incomming) == 0:
                                    connected = 0
                                    print 'the server terminated the connection'
                                    exit(1)
      
                                moretoparse, str_start_pos, msg = parse_message(original_in, str_start_pos, moretoparse)
                            else:
                                moretoparse, str_start_pos, msg = parse_message(original_in, str_start_pos, moretoparse)


                            if (moretoparse != -1): 
                                (connected, i,msg, aes_obj_enc, aes_obj_dec, message_recv,number, n, d, other_pub_n, other_pub_e, challenge) = do_things(connected, i,msg, aes_obj_enc, aes_obj_dec, message_recv,number, n, d, other_pub_n, other_pub_e, challenge)

                    

chatserv.close() #close connection

