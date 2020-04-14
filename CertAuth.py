import sys
import OpenSSL.crypto
import cryptography.x509
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

#Code by Atin Singhal & Prerana Mahalanobis
#Atin Singhal (ASU ID: 1217358454)
#Prerana Mahalanobis (ASU ID: 1217126352)

#InputArguments
#p12FilePath="/Users/atinsinghal97/Desktop/Project 4/Certificates/cert_bckup.p12" #sys.argv[1]
#rootCertificatePath="/Users/atinsinghal97/Desktop/Project 4/Certificates/root.crt" #sys.argv[2]
#clientCertificatePath="/Users/atinsinghal97/Desktop/Project 4/Certificates/subject.crt" #sys.argv[3]
#password="CSE539_Rocks!" #sys.argv[4]

if len(sys.argv)!=5:
    print ('Improper Input Argument')
    print ('Correct Format: python <file.py> <p12FilePath> <rootCertificatePath> <clientCertificatePath> <password>')
    sys.exit()

p12FilePath=sys.argv[1]
rootCertificatePath=sys.argv[2]
clientCertificatePath=sys.argv[3]
password=bytes(sys.argv[4],'utf-8')

if (".p12" not in p12FilePath) or (".crt" not in rootCertificatePath) or (".crt" not in clientCertificatePath):
    print ('Incorrect parameters. Try again with correct file format')
    print ('Correct Format: python <file.py> <p12FilePath> <rootCertificatePath> <clientCertificatePath> <password>')
    sys.exit()

#Initializing certificate objects

certObject=OpenSSL.crypto

clientCertificateFile=open(clientCertificatePath, 'rb').read()
clientCertificate=certObject.load_certificate(certObject.FILETYPE_PEM, clientCertificateFile)

p12File=open(p12FilePath, 'rb').read()
p12=OpenSSL.crypto.load_pkcs12(p12File, password)

rootCertificateFile=open(rootCertificatePath, 'rb').read()
rootCertificate=certObject.load_certificate(certObject.FILETYPE_PEM, rootCertificateFile)


#1- Verify Subject's certificate: True if valid, False otherwise

try:
    #print('Verify: ', clientCertificate.verify(clientCertificate.get_pubkey()))
    storeObject=OpenSSL.crypto.X509Store()
    storeObject.add_cert(rootCertificate)
    #print (storeObject)

    #forVerification=OpenSSL.crypto.X509StoreContext
    #forVerification.set_store(storeObject)
    forVerification = OpenSSL.crypto.X509StoreContext(storeObject, clientCertificate)
    forVerification.set_store(storeObject)
    forVerification.verify_certificate()
    print('')
    print('')
    print ('----------TASK 1----------')
    print ('Certificate Verification: True')

except Exception as e:
    print('')
    print('')
    print ('----------TASK 1----------')
    print('Certification Verification: False')
    #print('Error: ', e)


#2- Print Subject Name, Issuer, Serial Number, Encryption Algorithm, Not Valid Before, Not Valid After

print('')
print('')
print ('----------TASK 2----------')
print('Subject Common Name: ', clientCertificate.get_subject().commonName)
print('Issuer Common Name: ', clientCertificate.get_issuer().commonName)
print('Serial Number: ', clientCertificate.get_serial_number())
print('Encryption Algorithm:', clientCertificate.get_signature_algorithm().decode())
print('Not Valid Before: ', clientCertificate.get_notBefore().decode())
print('Not Valid After: ', clientCertificate.get_notAfter().decode())


#3- Print Subject's Public & Private Key

#print(clientCertificate.get_pubkey())
pubKeyObject=clientCertificate.get_pubkey()
pubKeyString=certObject.dump_publickey(certObject.FILETYPE_PEM, pubKeyObject)
print('')
print('')
print ('----------TASK 3----------')
print ('Public Key of Subject(n): ')
#print (pubKeyString)

pubKey = load_pem_public_key(pubKeyString, backend=default_backend()).public_numbers().n
print (pubKey)
e = load_pem_public_key(pubKeyString, backend=default_backend()).public_numbers().e
print('')
print ('e for Subject: ', e)

print('')

p12Certificate=p12.get_certificate()
p12Key=p12.get_privatekey()
#print (p12Key)
privateKeyString=OpenSSL.crypto.dump_privatekey(certObject.FILETYPE_PEM, p12Key)
print ('Private Key of Subject(d): ')
#print (privateKeyString)

privateKey = load_pem_private_key(privateKeyString, password=None,backend=default_backend()).private_numbers().d
print (privateKey)


#4- Print Public key of CA

#print(rootCertificate.get_pubkey())
rootPubKeyObject=rootCertificate.get_pubkey()
rootPubKeyString=certObject.dump_publickey(certObject.FILETYPE_PEM, rootPubKeyObject)
print('')
print('')
print ('----------TASK 4----------')
print ('Public Key of Certification Authority(n): ')
#print (rootPubKeyObject)
#print (rootPubKeyString)

rootPubKey = load_pem_public_key(rootPubKeyString, backend=default_backend()).public_numbers().n
print (rootPubKey)
eRoot = load_pem_public_key(rootPubKeyString, backend=default_backend()).public_numbers().e
print('')
print ('e for Certification Authority: ', eRoot)


#5- Print Hex Signature on Subject's Certificate

x509Object=cryptography.x509.Certificate

x509Certificate=cryptography.x509.load_pem_x509_certificate(clientCertificateFile, default_backend())
#x509Certificate=x509Object.load_certificate(certObject.FILETYPE_PEM, clientCertificateFile)

print('')
print('')
print ('----------TASK 5----------')
print ("Hex Signature of Subject's Certificate: ")
#print (x509Certificate.signature.encode('hex'))
print (x509Certificate.signature.hex())


#6- Encrypt String using RSA: b'Hello World'

message = b'Hello World'

#publicKey serialization
serializedPubKey= serialization.load_pem_public_key(
    pubKeyString,
    backend=default_backend()
)

#encryption
cipherText= serializedPubKey.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

#privateKey serialization
serializedPrivateKey= serialization.load_pem_private_key(
    privateKeyString,
    password= None,
    backend=default_backend()
)

plainText= serializedPrivateKey.decrypt(
    cipherText,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print('')
print('')
print ('----------TASK 6----------')
#print ('CipherText: ', cipherText.encode('hex'))
print ('CipherText: ', cipherText.hex())
print('')
print ('PlainText: ', plainText.decode())
print('')

