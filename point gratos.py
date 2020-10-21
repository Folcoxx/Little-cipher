#Programme pout CTF point by @Folcoxx

from crypto.Util.number import inverse
import binascii, base64, codecs
from binascii import hexlify

def help():

    print("rsaenc() chiffrage par public key")
    print("rsapub() dechiffrage par public key")
    print("rsafacto() dechiffrage par Modulus")
    print("dcodehex() hex vers autre base")
    print("dcodeascii() ascii vers d'autres bases")
    print("dcodedec() decimal vers d'autres bases")
    print("decodeb64(*) *= 1 for encode or 2 for decode")
    print("decodeb32(*) *= 1 for encode or 2 for decode")
    print("dcodecesar(*,$) *= 1 for encode or 2 for decode, $= b for bruteforce or k pour key")
    print("")


def dcodedec():
    
    m = input("message decimal m = ")

    i = int(m)
    hexa = format(i, 'x')
    binari = format(i, 'b')
    
    #list = [i]
    #ascII = [] 
    #for ele in list: 
    #    ascII.extend(chr(num) for num in ele)

    print("En binaire : ",binari)
    #print("En Ascii : ", ascII)
    print("En Hexadecimal : ", hexa)
    

def decodeb32(text):
    if (text == 1):
        menc = input("message à encoder m = ")
        m = menc.encode('ascii')
        s = base64.b32encode(m)
        base32_m = s.decode('ascii')
        print("Message en B32 :", base32_m)
    elif (text == 2):
        mdec= input("message à decoder m = ")
        m = mdec.encode('ascii')
        s = base64.b32decode(m)
        ascii_m = s.decode('ascii')
        print("Message en ascii :", ascii_m)
    else :
        print("mauvaise valeur decodeb32(*) *= 1 for encode or 2 for decode")
def decodeb64(text):
    if (text == 1):
        menc = input("message à encoder m = ")
        m = menc.encode('ascii')
        s = base64.b64encode(m)
        base64_m = s.decode('ascii')
        print("Message en B64 :", base64_m)
    elif (text == 2):
        mdec= input("message à decoder m = ")
        m = mdec.encode('ascii')
        s = base64.b64decode(m)
        ascii_m = s.decode('ascii')
        print("Message en ascii :", ascii_m)
    else :
        print("mauvaise valeur decodeb64(*) *= 1 for encode or 2 for decode")
    

def dcodeascii():

    #Message ascii
    
    m = input("message ASCII m = ")
    encoding='utf-8'

    binari = bin(int(binascii.hexlify(m.encode(encoding)), 16))[2:]
    list = [m]
    dec = [] 
    for ele in list: 
        dec.extend(ord(num) for num in ele) 
    #dec = ord(m)
    str = m.encode()
    hexa = hexlify(str).decode()

    print("En binaire : ",binari)
    print("En decimal : ", dec)
    print("En Hexadecimal : ", hexa)
    
def dcodehex():

    #Message Hex
    
    m = input("message hex m = ")

    #dcode en ascii
    
    ascII = bytes.fromhex(m).decode('ascii')

    #dcode en decimal
    
    dec = int(m, 16)

    #dcode en binaire
    
    binari = bin(dec)[2:]


    print("En ascii : ", ascII)
    print("En decimal : ", dec)
    print("En binaire : ",binari)
    
def rsaenc():

    #m  message en claire

    m = int(input("Message en claire m = "))

    #n = pq (Modulus)

    n = int(input("Modulus n = "))

    #Exposant

    e = int(input("Exposant e = "))

    #Calcule du message chiffre c

    c = m**e % n

    print("Le message chiffré est", c )
    
def rsadec():
    
    #n = pq (Modulus)

    n = int(input("Modulus n = "))

    #Exposant

    e = int(input("Exposant e = "))
    
    #c  message chiffre

    c = int(input("Message chiffre c = "))

    #Calcule du message avec Pub Key

    m = pow(c, e, n)

    #print("Le message déchiffré est :",m)
    print(bytes.fromhex(hex(m)[2:]).decode())
    
def rsapq():
    #(n,e) public key 
    #n = pq (Modulus)

    n = int(input("Modulus n = "))

    #Exposant

    e = int(input("Exposant e = "))

    #c  message chiffre

    c = int(input("Message chiffre c = "))

    #p et q sont les facteurs premiers de n

    p = int(input("Facteur p = "))
    q = int(input("Facteur q = "))

    # phi correspond a la valeur de l'indicatrice d'Euler en n
    phi = (p - 1) * (q - 1)

    #d est la clef privee
    d = inverse(e, phi)                                                                                                                                                                                                                                                                                                                                                                                                                                                                       # Pour dechiffrer, on utilise d (inverse de modulus phi) et le message est dechiffre                                                                                                                                                         m = pow(c, d, n)

    #Calcule du message avec Clé prive

    m = pow(c, d, n)

    #print("Le message déchiffré est :",m)
    print(bytes.fromhex(hex(m)[2:]).decode())
