
# cpp-ransomware
 C\C++ Ransomware example using RSA and AES-128 with BCrypt library on Windows

<h1>Usage</h1>

```
Ransomware.exe -e [Filename]          Encrypts a file, output will be <Filename>.ransom
Ransomware.exe -d [Filename.ransom]   Decrypts a file, output will be <Filename>.clean
```

<h2>Functionality</h2>

**Encryption:**

 - Read all input file content to a buffer
 - using BCrypt APIs
 - Generate IV and AES-128 key
 - Encrypt AES key with RSA public key 
 - Encrypt file content with AES-128
 - Create a file with original filename but with .ransom extension
 - Store IV and encrypted AES key on the output file

**Decryption:**

 - Read all input file content to a buffer
 - Extract IV, encrypted AES key and encrypted file data
 - Decrypt AES key
 - Decrypt file data with IV and AES Key
 - Create a file with original filename but with .clean extension

<h2>Tutorial</h2>

Using OpenSSL generate a RSA keypair, the application expects `private.pem` and `public.pem` to be placed at the root directory.

```
cd approot
openssl genrsa -out private.pem
openssl rsa -in private.pem -pubout -out public.pem
openssl pkey -in private.pem -out private.pem
```

<h2>Reminders</h2>

This source code wasn't created to be used as a malware but simply as a mere example, ence why it's functionalities are not really as how a real ransomware works.
