import random
import TSE
print("-------------------CASE 3 Starts-------------------")
n = 10
k = random.randint(10,1024)
t = 7
(sk,pp) = TSE.Setup(k,n,t)
(ppDP,ppCom) = pp
m = 'It is a secret message I want to send'
j = 3
print(f'Encryptor: {j}')
# member starts from 0 .... n-1
S = {0,2,4,5,6,7,8}
print(f'Contatcted party in Encryption: {S}')
EncParty = (j,m,S)
c3 = TSE.DistEnc(sk,EncParty,pp,t)
j2 = 1
DecParty = (j2,c3,S)
print(f'Decryptor: {j2}')
print(f'Contatcted party in Decryption: {S}')
p = TSE.DistDec(sk,DecParty,pp,t)
print(f'Recovered message: {p}')
print("-------------------CASE 3 Ends-------------------")