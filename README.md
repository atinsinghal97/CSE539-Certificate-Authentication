# Certificate-Authentication

**Objectives -**
Students will be able to:
- Differentiate digital certificates and certification authority (CA)
- Encrypt and decrypt strings with RSA using public and private keys
- Explain ubiquity

**Technology Requirements**
- Python 3 on Linux


**Project Description**
- In cryptography, a certification authority (CA) is an entity that issues digital certificates. A CA acts as a trusted third party who can be trusted both by the owner of the certificate and the party relying upon the certificate. A digital certificate certifies that a public key is owned by the named owner of the certificate (subject). The format of these certificates is specified by the X.509 or OpenSSL standards. A very common use for certificate authorities is to sign certificates used in HTTPS, the secure browsing protocol for the WWW.
- A certificate is essential to circumvent a malicious party which happens to be on the route to a target server which acts as if it were the target. The client (your browser) uses the CA certificate to authenticate the CA signature on the server certificate as part of the authorizations before launching a secure connection. Usually, browsers include a set of trusted CA certificates. The quantity of internet browsers, other devices, and applications which trust certificate authority is referred to as ubiquity.


**Directions**

For this assignment you have been provided 3 certificates in the certificate.zip file:

- A public certificate (subject.crt)
- A backup file containing the private key corresponding to it (cert_bckup.p12)
  - Password on the .p12 file: CSE539_Rocks!
- The CA public certificate (root.cer)

Write a Python 3 program to do tasks 1-6. For each task, you should print out the relevant value as a line of text.

1. Verify the Subject’s certificate (print True if valid, False otherwise)
2. Print the following form on the Subject’s certificate (where applicable, print the common name):
   - Subject name
   - Issuer
   - Serial Number
   - Encryption Algorithm
   - Not Valid Before
   - Not Valid After
3. Print the Subject’s public and private key (the public key is represented by the integers n and e; and, the private key, by the integer d)
   - Public Key Modulus (n)
   - Public Key Exponent (e)
   - Private Key Exponent (d)
4. Print the public Key of Certification Authority.
   - Root Public Key Modulus (n)
   - Root Public Key Exponent (e)
5. Print the hex signature on the Subject’s certificate
6. Encrypt the following string using RSA: b’Hello World’. Use OEAP padding, the mask generation function MGF1, and the SHA256 hash function. Note that encryption may not produce deterministic results. You can verify your encryption algorithm by writing a decryption algorithm in the same way. For encryption, use the subject’s public key. For decryption, use the subject’s private key.

For submission, your program should work with any files from the command line. You will receive as input, in order: the p12 file path, the CA (root) crt file path, the client (subject) crt file path, and the password. A sample of running the program with the given input files and a sample output is included at the end of this document. As mentioned above, encrypt may return a different value.


 How to Run?
------------

Arguments to be passed to run the code:
- FILE-NAME
- P12-FILE-PATH
- ROOT-CERTIFICATE-PATH
- CLIENT-CERTIFICATE-PATH
- PASSWORD

Example:
~~~
python3 CertAuth.py /Users/Desktop/Project\ 5/Certificates/cert_bckup.p12 /Users/atinsinghal97/Desktop/Project\ 5/Certificates/root.crt /Users/Desktop/Project\ 5/Certificates/subject.crt CSE539_Rocks!
~~~

Requirements
------------
The program needs the following packages:
	1. OpenSSL
	2. cryptography

'OpenSSL' & cryptography' can be installed by running the following commands in the Terminal:

	pip install cryptography
	pip install pyopenssl
