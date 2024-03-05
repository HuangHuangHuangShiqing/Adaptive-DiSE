#using python3.11
import random
import SCom
import lagrange
import shamirs
from Crypto.Util.number import getPrime
from Crypto.Hash import SHA256


def generator(p):
    # return g
    for i in range(2,p-1):
        # i^(p-1) % p = 1 means i^(1,...,p-1) % p = 1 ... p-1
        if pow(i,p-1,p) == 1 and all(pow(i, (p-1)//f, p) != 1 for f in range(2,5)):
            return i
    return None

def hashFunction(x,p):
    # return (w1,w2)
    h = SHA256.new(x.encode()).digest()
    return (int.from_bytes(h[:len(h)//2], 'big') % p,int.from_bytes(h[len(h)//2:], 'big') % p)

def hashChallenge(t,t1,t2):
    '''
     Hash t,t1,t2
     return H'(t,t1,t2)
    '''
    hByte = t.to_bytes((t.bit_length()+7)//8, 'big')
    h1Byte = t1.to_bytes((t1.bit_length()+7)//8, 'big')
    h2Byte = t2.to_bytes((t2.bit_length()+7)//8, 'big')
    concatenateHash = hByte + h1Byte + h2Byte
    h = SHA256.new(concatenateHash).digest()
    return int.from_bytes(h,'big')

def Prov(stmt,sk,p,ppCom):
    '''
     prove
     parameter sk: sk = (ui,vi,rho1i,rho2i) where i belongs to S
     parameter stmt: (x,z,c1,c2)
            x: message x
            z: z = w1^ui * w2^vi % p where i belings to S 
            c1: commit(ui,rho1i)
            c2: commit(vi,rho2i)
     parameter p: prime number
     parameter ppCom: (g,h)
     return pi = (t,t1,t2),e,(u1,u2,u3,u4)
        t = w1^v1 * w2^v2 
        t1 = Com(v1,v3)
        t2 = Com(v2,v4) where v1,v2,v3,v4 are random generated from Zp
        e = H'(t,t1,t2)
        u1 = v1 + e*ui
        u2 = v2 + e*vi
        u3 = v3 + e*rho1i
        u4 = v4 + e*rho2i
    '''
    x,z,c1,c2 = stmt
    u,v,rho1,rho2 = sk
    # w1,w2 = z
    # print(f'(u,v,rho1,rho2) {u,v,rho1,rho2}')
    # Prove
    # Sample randomnesses (v1,v2,v^1,v^2) : (v1, v2, v3, v4) from Zp.
    v1 = random.randint(1,p-1)
    v2 = random.randint(1,p-1)
    v3 = random.randint(1,p-1)
    v4 = random.randint(1,p-1)
    # print(f'(v1,v2,v3,v4) {v1,v2,v3,v4}')
    w1,w2 = hashFunction(x,p)
    # t = (w1^v1)*(w2^v2), t1 = Com(v1,v3), t2 = Com(v2,v4)
    t = (pow(w1,v1,p) * pow(w2,v2,p))%p
    t1 = SCom.Com(v1,ppCom,v3,p)
    t2 = SCom.Com(v2,ppCom,v4,p)
    #Attack 2: e cannot be 0 failed
    e = hashChallenge(t,t1,t2) % p
    #ui := vi + eki
    u1 = (v1 + e * u.value) #% p
    u2 = (v2 + e * v.value) #% p
    # uˆi := vˆi + eρi 
    u3 = (v3 + e * rho1) #% p
    u4 = (v4 + e * rho2) #% p
    # print(f'(w1,w2) {w1,w2}')
    return (t,t1,t2),e,(u1,u2,u3,u4)

def Verify(stmt,pi):
    '''
     verify
     parameter stmt: stmt = (x,hi,(c1,c2),p,ppCom)
        # x: message
        # hi: w1^ui * w2^vi
        # c1: Com(ui,rho1i) = gammai
        # c2: Com(vi,rho2i) = deltai
        # p: prime number
        # ppCom: (g,h)
     parameter pi: pi = ((t,t1,t2),e,(u1,u2,u3,u4))
     return 1 if only if all of following equations succeeds, and 0 otherwise
         e = H'(t,t1,t2)
         w1^u1 * w2^u2 = t*z^e
         h^u3 * g^u1 = t1 * c1^e
         h^u4 * g^u4 = t2 * c2^e
    '''
    x,z,(c1,c2),p,(g,h) = stmt
    # print(f'Verify stmt: (x,z,(c1,c2),p,(g,h)) {stmt}')
    (t,t1,t2),e,(u1,u2,u3,u4) = pi
    # print(f'Verify pi:  (t,t1,t2),e,(u1,u2,u3,u4) {pi}')
    # u,v,rho1,rho2 = sk
    # compute (w1,w2) = H(x)
    w1,w2 = hashFunction(x,p)
    # print(f'verfiy w1,w2 {w1,w2}')
    # print('verfiy starts:')

    # e = H'(t,t1,t2)
    htt1t2 = hashChallenge(t,t1,t2) % p
    if e != htt1t2:
        print(f'e: {e} H\'(t,t1,t2): {htt1t2}')
        return 0
    # print('Statement 1 pass')

    # w1^u1 * w2^u2 = t*z^e
    w1w2 = (pow(w1,u1,p) * pow(w2,u2,p)) % p
    tze = (t * pow(z,e,p)) % p
    if  w1w2 != tze:
        print(f'w1w2: {w1w2} tze: {tze}')
        return 0
    # print('Statement 2 pass')

    # h^u3 * g^u1 = t1 * c1^e
    hu3gu1 = (pow(h,u3,p) * pow(g,u1,p)) % p
    t1c1e = (t1 * pow(c1,e,p)) % p
    if hu3gu1 != t1c1e:
        print(f'hu3gu1: {hu3gu1} t1c1e: {t1c1e}')
        return 0
    # print('Statement 3 pass')

    # h^u4 * g^u4 = t2 * c2^e
    hu4gu2 = (pow(h,u4,p) * pow(g,u2,p)) % p
    t2c2e = (t2 * pow(c2,e,p)) % p
    if hu4gu2 != t2c2e:
        print(f'hu4gu2: {hu4gu2} t2c2e: {t2c2e}')
        return 0
    # print('Statement 4 pass')
    return 1
    
def Setup(k,n,t):
    '''
     distrubte the key
     parameter k: bit of p/secret parameter
     parameter n: number of shares
     parameter t: threshold
     return sk,pp
     sk is 2D list
         sk[i] = [ui,vi,rho1i,rho2i] sk[i][0] = ui, sk[i][1] = vi, sk[i][2] = rho1i, sk[i][3] = rho2i
     pp is public parameters pp = [t,p,g,GaDe,ppCom]
         t: threshold
         p: prime number
         g: generator of p
         GaDe: a set of (gamma,delta)
         ppCom = [g,h]
    '''
    pp =[]
    pp.append(t)
    # Atack 1: if p is small value, it is easy to break the DH # p at least 10 bits and most 1024 bits
    p = getPrime(k)
    # print(f'p is {p}')
    pp.append(p)
    g = generator(p)
    pp.append(g)
    # print(f'g is {g}')
    # seceret parament SK=(u,v)
    SK = [random.randint(1,p-1),random.randint(1,p-1)]
    # print(f'(u,v) {(SK[0],SK[1])}')
    U = shamirs.shares(SK[0],quantity=n, threshold=t, modulus = p)
    # print(U)
    V = shamirs.shares(SK[1],quantity=n, threshold=t, modulus = p)
    # print(V)
    # print(f'ui,vi {(su.value,sv.value) for su,sv in zip(U,V)}')
    # gamma&delta set
    GaDe = []
    sk = []
    # x = random.randint(1,p-2)
    # print(f'x is {x}')
    ppCom = SCom.Setupcom(k,g,p)
    # h = pow(g,k,p)
    # ppCom = (g,h)
    for ui,vi in zip(U,V):
        rho1 = random.randint(1,p-1)
        rho2 = random.randint(1,p-1)
        #gamma: related to u and rho1
        gamma = SCom.Com(ui.value,ppCom,rho1,p)
        #delta: related to v and rho2
        delta = SCom.Com(vi.value,ppCom,rho2,p)
        GaDe.append((gamma,delta))
        sk.append((ui,vi,rho1,rho2))
    # sk = [(ui,vi) for ui,vi in zip(U,V)]
    pp.append(GaDe)
    pp.append(ppCom)
    # print(f'GaDe is {GaDe}')
    # print(f'(g,h)) is {ppCom}')
    return sk,pp

def Eval(ski,x,pp):
    '''
     DPRFk(x) = H(x)^u * G(x)^v = h
     parameter ski: ski = (ui,vi,rho1i,rho2i)
     parameter x: message
     parameter pp: public parameters pp = [p,g,GaDe,ppCom]
     return (w1,w2,zi),PIi
         w1 = upper half part of H(x)
         w2 = lower half part of H(x)
         zi = w1^ui*w2^vi
         PIi = ((t,t1,t2),e,(u1,u2,u3,u4))
            t = w1^v1 * w2^v2 
            t1 = Com(v1,v3)
            t2 = Com(v2,v4) where v1,v2,v3,v4 are random generated from Zp
            e = H'(t,t1,t2)
            u1 = v1 + e*ui
            u2 = v2 + e*vi
            u3 = v3 + e*rho1i
            u4 = v4 + e*rho2i
    '''
    t,p,g,GaDe,ppCom = pp
    u,v,rho1,rho2 = ski
    # print(f'Eval (ui,vi) {u,v}')
    w1,w2 = hashFunction(x,p)
    # print(f'Eval (w1,w2) {w1,w2}')
    # zi  = w1^ui * w2^vi % p 
    zi = (pow(w1,u.value,p) * pow(w2,v.value,p)) % p
    c1 = SCom.Com(u.value,ppCom,rho1,p)
    c2 = SCom.Com(v.value,ppCom,rho2,p)
    pi = Prov((x,zi,c1,c2),ski,p,ppCom)#Prov(ski,(w1,w2),p,ppCom)
    # print(f'Eval pi:  (t,t1,t2),e,(u1,u2,u3,u4) {pi}')
    return (w1,w2,zi),pi

def Combine(skShare,pp,x):
    '''
     reconstruct the secrete from at least t parties
     parameter skShare: (i,zi)
         zi = (w1,w2,hi),PIi
         PIi = (t,t1,t2),e,(u1,u2,u3,u4)
     parameter pp: public parameter pp = [p,g,GaDe,ppCom]
     parameter t: threshold
     parameter x : message
     return z : w1^u * w2^v = hi^Coefficienti for i belong to S
    '''
    t,p,g,GaDe,ppCom = pp
    if len(skShare) < t:
        return None
    # print(f'type of skShare {type(skShare)}')
    # print(f'DPRF: shares(index,(w1,w2,zi),pi])')
    # print(skShare)
    # i = 0
    # indices of involving parties
    X = [i for i,_ in skShare]
    Y = []
    # # print(f'S = {S}')
    z = 1
    hiset = []
    for i,zi in skShare:
        (w1,w2,hi), PIi = zi
        if Verify((x,hi,GaDe[i-1],p,ppCom),PIi) != 1:
            return None
        Y.append((i,hi))
    # print(Y)
    Y.sort()
    # print(D)
    z = lagrange.interpolate(Y,p,t-1)
    #return 2
    return z # h0 #,z
    
'''
#example 
#(failed)attack 1: w1,w2 and hi are known, do re = hi/((w1)*(w2)) until result is not integer 
# and count how many division has been operated
#then muliply w1w2 back, then divide w1 or w2
#if re/w1 is not interger, the ui = count
#else vi = count
    # def parse(w1,w2,h,p):
    #     w = (w1 * w2) % p
    #     reminder = h % w
    #     count = (h - reminder) / w
    #     newH = h - h * w
    #     if(newH w1) ==> not work since %p is here to protect h(DDH dicisional diffie hellman)
n = 10
k = 5 #random.randint(10,1024)
t = 7
(sk,pp) = Setup(k,n,t)
# ui,vi,rho1,rho2 = sk
#print(f'sk(ui,vi,rho1,rho2) : {sk}')
# print(f'pp(p,g,GaDe(gammaC1,deltaC2),[g,h]): {pp}')
p = pp[0]
x = 'message'
#shares[i] = [index,hi]
#print(sk[0][1],sk[1][1])
shares = [(i, Eval(sk[i-1],x,pp)) for i in range(1,n+1)]
w1,w2,hi = shares[0][1][0][0],shares[0][1][0][1],shares[0][1][0][2]
# print(f'shares(index,(w1,w2,zi),pi]')
print(shares)
# combine = Combine(sk[:t+1],pp,t,x)
combine = Combine(shares,pp,t,x)
print(f'combin 1-10: {combine}')
combine = Combine(shares[:t],pp,t,x)
print(f'combine 1-t: {combine}')
combine = Combine(shares[2:t+2],pp,t,x)
print(f'combine 2-t+2: {combine}')
combine = Combine((shares[6],shares[0],shares[5],shares[8],shares[7],shares[4],shares[3]),pp,t,x)
print(f'combine: {combine}')
combine = Combine((shares[6],shares[1],shares[5],shares[8],shares[2],shares[4],shares[3]),pp,t,x)
print(f'combine: {combine}')
#print((shares[4],shares[1],shares[2],shares[3],shares[6],shares[5],shares[8],shares[7]))
'''
