from Crypto.PublicKey import RSA

n = 85161183100445121230463008656121855194098040675901982832345153586114585729131
e = 65537
p = 280651103481631199181053614640888768819
q = 303441468941236417171803802700358403049
m = n-(p+q-1)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

d = modinv(e,m)
key = RSA.construct((n,long(e),d,p,q))
print(key.exportKey())
