# Crypto - Integrity

    Just a simple scheme.
    nc 202.120.7.217 8221


Service code:

```python
#!/usr/bin/python -u

from Crypto.Cipher import AES
from hashlib import md5
from Crypto import Random
from signal import alarm

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]


class Scheme:
    def __init__(self,key):
        self.key = key

    def encrypt(self,raw):
        raw = pad(raw)
        raw = md5(raw).digest() + raw

        iv = Random.new().read(BS)
        cipher = AES.new(self.key,AES.MODE_CBC,iv)

        return ( iv + cipher.encrypt(raw) ).encode("hex")

    def decrypt(self,enc):
        enc = enc.decode("hex")

        iv = enc[:BS]
        enc = enc[BS:]

        cipher = AES.new(self.key,AES.MODE_CBC,iv)
        blob = cipher.decrypt(enc)

        checksum = blob[:BS]
        data = blob[BS:]

        if md5(data).digest() == checksum:
            return unpad(data)
        else:
            return

key = Random.new().read(BS)
scheme = Scheme(key)

flag = open("flag",'r').readline()
alarm(30)

print "Welcome to 0CTF encryption service!"
while True:
    print "Please [r]egister or [l]ogin"
    cmd = raw_input()

    if not cmd:
        break

    if cmd[0]=='r' :
        name = raw_input().strip()

        if(len(name) > 32):
            print "username too long!"
            break
        if pad(name) == pad("admin"):
            print "You cannot use this name!"
            break
        else:
            print "Here is your secret:"
            print scheme.encrypt(name)


    elif cmd[0]=='l':
        data = raw_input().strip()
        name = scheme.decrypt(data)

        if name == "admin":
            print "Welcome admin!"
            print flag
        else:
            print "Welcome %s!" % name
    else:
        print "Unknown cmd!"
        break
```

First, let's sum up what we know about the system:

1. AES-128-CBC
2. Login gets prepended with an MD5(login)
3. Logins are 32 symbols max
4. Input to [r]egister is checked for padding before passing to the encryption routine (so you cannot pass 'admin\x0b..\x0b' and get a candy)

**Goal:** login as 'admin' and get the flag

Upon seeing CBC mode I immediately reached out to not Wikipedia but my handwritten notes for Stanford Crypto I (yeah, I'm a huge nerd). After fiddling with them a bit I got this idea: we need to pass 2-block secret with correctly padded 'admin' in the last block (with 11 '\x0b' symbols) and an MD5 hash for it in the first block (both encrypted, of course), but since we cannot pass it as an original login, we will go a bit beyond and receive a 3-block secret by passing a login that starts with 'admin\x0b..\x0b', drop the last block and then forge the valid prefix for the remainder.

Now if you would to recall the [decryption routine from the Wikipedia](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_.28CBC.29) (because you don't have access to my notes… duh), the 'admin' ciphertext will be passed to the decryption routine and then ⊕-ed with the previous block of the ciphertext, resulting in the correctly padded 'admin' – which is our goal – but the previous block ('hash'-ciphertext) will decrypt to **[md5('admin\x0b..\x0b' + 'garbage+padding')]** ⊕ **[original IV]**. After getting ⊕-ed with the **[original IV]** this will result in the bad checksum. So we need to construct a correct IV + encrypted MD5 prefix first. 

Since the IV is just prepended and is not modified by any process, passing the correct IV will solve the problem. So if we want the first block to decrypt to **[md5('admin\x0b..\x0b')]**, we need to solve the following equation for **[Y]**:

**[md5('admin\x0b..\x0b')]** = **[md5('admin\x0b..\x0b' + 'garbage+padding')]** ⊕ **[original IV]** ⊕ **[Y]**

**[Y]** = **[md5('admin\x0b..\x0b')]** ⊕ **[md5('admin\x0b..\x0b'] + 'garbage+padding')]** ⊕ **[original IV]**

And that's our **[new IV]**. So:

    Old secret: [original IV] [CT for original hash] [CT for padded admin] [CT for garbage]
    New secret: [new IV]      [CT for original hash] [CT for padded admin]

Let's write a script now, shall we? (inb4, 'ugh, Python 2', but sockets in Py3 operate on bytes which'll result in a lot of additional conversions)

```python
import socket
from hashlib import md5

BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 
unpad = lambda s : s[0:-ord(s[-1])]

def xor(a, b):
    return ''.join(chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect(("202.120.7.217",8221))

# Get header
print(s.recv(1024))

s.send('r\n')  # Send '[r]egister request'

uname = 'admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b'  # Correctly padded 'admin'
ext = 'whatever'  # Garbage to force the 3rd block

s.send(uname + ext + '\n')  # Send login

print(s.recv(1024))
print(s.recv(1024))
data = s.recv(1024).split('\n')[1]  # Receive secret (don't need to see it, so no 'print')
ct = data.decode('hex')

ct = ct[:-16]  # Discard the 3rd block

# Forge IV
old_iv = ct[:16]
hash1 = md5(uname).digest()
hash2 = md5(pad(uname + ext)).digest()
new_iv = xor(old_iv, hash1)
new_iv = xor(new_iv, hash2)

new_ct = new_iv + ct[16:]  # Construct new secret

s.send('l\n')  # Send '[l]ogin' request
s.send(new_ct.encode('hex') + '\n')  # Send forged secret

# G1mm3 y0ur 53cr375!
print(s.recv(1024))
print(s.recv(1024))

s.close()
```

Running that against the service will return us the flag:

```
iffnty@terminal ~/Downloads> python solve_integrity.py
Welcome to 0CTF encryption service!

Please [r]egister or [l]ogin

Here is your secret:
Welcome admin!

flag{Easy_br0ken_scheme_cann0t_keep_y0ur_integrity}

Please [r]egister or [l]ogin
```