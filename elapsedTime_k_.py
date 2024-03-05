import time
import random
import TSE
n = 10
t = 7
for i in range(0,30):
    print(f'-------------------Round {i+1} Starts-------------------')
    k = random.randint(10,1024)
    print(f'secret parameter {k}')

    (sk,pp) = TSE.Setup(k,n,t)
    (ppDP,ppCom) = pp
    # m = 'It is a secret message I want to send'
    m = 'It is a secret message I want to send'
    j = 3
    # member starts from 0 .... n-1z
    S = {0,2,4,5,6,7,8}
    EncParty = (j,m,S)
    startEnc = time.time()
    c3 = TSE.DistEnc(sk,EncParty,pp,t)
    EndEnc = time.time()
    print(f'Encryption: Elapsed Time: {EndEnc-startEnc}')
    DecParty = (j,c3,S)
    # print(f'Decryptor: {j}')
    # print(f'Contatcted party in Decryption: {S}')
    startDec = time.time()
    p = TSE.DistDec(sk,DecParty,pp,t)
    EndDec = time.time()
    print(f'Decryption: Elapsed Time: {EndDec-startDec}')
    print(f'Length of recovered message: {len(p)}')