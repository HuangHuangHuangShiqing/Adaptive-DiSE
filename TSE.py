import DPRF
import SCom
import random
from Crypto.Hash import SHA256
from Crypto.Cipher import Salsa20
S_database = None
def xor(m,s):
   '''
      return m ^ s
   '''
   lenM = len(m)
   lenS = len(s) 
   length = max(lenM,lenS)
   sLen = 0
   mLen = 0
   # Padding s with leading zeros if it is shorter than m
   if lenS < lenM:
      sLen = lenM - lenS
      s = '0' * (lenM - lenS) + s
   elif lenS > lenM:
      mLen = lenS - lenM
      m = '0' * (lenS - lenM) + m
   result = ''.join(['1' if m[i] != s[i] else '0' for i in range(length)])
   #  print('xor')
   #  print(len(m))
   #  print(len(s))
   return result#,sLen,mLen

def Setup(k,n,t):
   '''
      parameter k: bit of p
      parameter n: number of shares
      parameter t: threshold(at least combine t partial keys to get whole key)
      return sk,pp
       sk is 2D list
         sk[i] = [ui,vi,rho1i,rho2i] sk[i][0] = ui, sk[i][1] = vi, sk[i][2] = rho1i, sk[i][3] = rho2i
       pp is public parameters pp = [ppDP,ppCom]
       ppDP = [p,g,GaDe,ppComDP]
         p: prime number
         g: generator of p
         GaDe: a set of (gamma,delta)
         ppComDP = [g,h]
       ppCom = [g,h]
      
   '''
   sk,ppDP = DPRF.Setup(k,n,t)
   t,p,g,GaDe,ppComDP = ppDP
   ppCom = SCom.Setupcom(k,g,p)
   global S_database
   S_database = {i: [] for i in range(n)}
   # print(S_database)
   return sk,(ppDP,ppCom)

def DistEnc(sk,EncParty,pp,t):
   '''
       parameter sk: a list of secrete keys [u,v,rho1,rho2]
       parameter EncParty: [j,m,S]
         j: index of encryptor
         m: message
         S: set of index of parties helping in encryption
       parameter pp: a public parameters pp = [ppDP,ppCom]
       parameter t: threshold
       return j,a,e
         j: index of encryptor
         a:com(m,ppCom,rho,p)
         e: nonce || PRG(w) xor m||p
   '''
   ppDP,ppCom = pp
   t,p,g,GaDe,ppComDP = ppDP
   j,m,S = EncParty
   mByte = m.encode()
   mInt = int.from_bytes(mByte, 'big')
   rho = random.randint(1,p-1)
   # print(f'Enc rho {rho}')
   a = SCom.Com(mInt,ppCom,rho,p)

   # j||a
   ja = str(j) + str(a)
   # print(S)
   # send a to all parties in S
   for i in S:
          S_database[i].append(a)
   z = []
   # print(S_database)
   for i in S:
      zi = DPRF.Eval(sk[i],ja,ppDP)  
      z.append((i+1,zi))
      #partiesSk.append(sk[i])
   # print(f'TSE: shares(index,(w1,w2,zi),pi])')
   # print(z)
   w = DPRF.Combine(z,ppDP,ja)
   #print(f'ENC k : {w}')
   if w is None:
      return None
   #PRG(w):
   # nonce = random.randint(1,p-1)
   # hash key as 256 bits to fit in Salsa20
   keyByte = w.to_bytes((w.bit_length()+7)//8, 'big')
   hashedKey = SHA256.new(keyByte).digest()
   # print(f'ENC hashedKey : {hashedKey}')
   cipher = Salsa20.new(hashedKey)
   # print('nonce')
   # print(cipher.nonce)
   prg = cipher.encrypt(hashedKey)
   # print(prg)
   nonce = ''.join(f'{byte:08b}' for byte in cipher.nonce)
   # print(len(nonce))
   # key =  w.to_bytes(32, 'big')
   # # print(f'key = {w}')
   # cipher = AES.new(key,AES.MODE_CTR)
   # prg = cipher.encrypt(key)
   # print(f'TSE PRG(x)')
   # print(prg)
   rhoStr = str(rho)
   rhoLen = len(rhoStr)
   mrho = (str(rhoLen) + '|' + m + rhoStr).encode()
   # print(f'ENC mrhoByte {mrho}')
   # print(f'len rho: {len(str(rho))}')
   # print(f'TSE m||rho')
   # print(mrho)
   pgrbit = ''.join(f'{byte:08b}' for byte in prg)
   # print(f'ENC pgrbit')
   # print(pgrbit)
   mrhobit = ''.join(f'{byte:08b}' for byte in mrho)
   # print(f'ENC mrhobit')
   # print(mrhobit)
   
   e = xor(pgrbit,mrhobit)
   e = nonce + e
   # print('ENC e')
   # print(e)
   return j,a,e

def DistDec(sk,DecParty,pp,t):
   '''
      parameter sk: a list of secrete keys [u,v,rho1,rho2]
      parameter DecParty: [j',c,S]
         j': decryptor
         c: j,a,e
      parameter pp: a public parameters pp = [ppDP,ppCom]
      parameter t: threshold
      return m
   '''
   ppDP, ppCom = pp
   t,p,g,GaDe,ppComDP = ppDP
   jPrime,c,S = DecParty
   j,a,e = c
   # j||a
   if jPrime != j:
      return None
   ja = str(j) + str(a)
   flag = False
   for i in S:
        for a_prime in S_database[i]:
           if a == a_prime:
               flag = True
               break
  
   if not flag:
      return None

   z = []
   for i in S:
      zi = DPRF.Eval(sk[i],ja,ppDP)  
      z.append((i+1,zi))
      #partiesSk.append(sk[i])
   w = DPRF.Combine(z,ppDP,ja)
   #print(f'DEC k : {w}')
   if w is None:
          return None
   # print(f'TSE: shares(index,(w1,w2,zi),pi])')
   # print(z)
   #prg(w) salsa20
   # bit to byte
   nonce = bytes(int(e[i : i + 8], 2) for i in range(0, 64, 8))
   # print(nonce)
   keyByte = w.to_bytes((w.bit_length()+7)//8, 'big')
   hashedKey = SHA256.new(keyByte).digest()
   cipher = Salsa20.new(hashedKey,nonce)
   prg = cipher.encrypt(hashedKey)

   #change prg to bit
   pgrbit = ''.join(f'{byte:08b}' for byte in prg)
   #print(f'DEC pgrbit')
   #print(pgrbit)
   #print(f'DEC e')
   #print(e)
   # pgr(x) ^ e
   mrhobit = xor(pgrbit,e[64:])
   # print(f'DEC mrhobit {mrhobit}')
   #mrhobit = mrhobit[len(mrhobit)-mrhobitLen:]
   # print(f'DEC mrhobit {mrhobit}')
   mrhoByte = bytes(int(mrhobit[i : i + 8], 2) for i in range(0, len(mrhobit), 8))
   try:
      mrhoStr = mrhoByte.decode('utf-8')
   except:
      print("Different contacted parties in encryption and decryption")
      return None
   try:
      rhoLenStr,mrho = mrhoStr.split('|',1)
   except:
      print("Different contacted parties in encryption and decryption")
      return None
   rhoLen = int(rhoLenStr)
   # print(f'DEC mrhoByte {mrhoByte}')
   m = mrho[:-rhoLen]
   # print(f'DEC mByte {mByte}')
   mInt = int.from_bytes(m.encode(), 'big')
   rhoStr = mrho[-rhoLen:]
   # print(f'DEC rhoByte {rhoByte}')
   rho = int(rhoStr)
   # print(f'DEC rho {rho}')
   if (a != SCom.Com(mInt,ppCom,rho,p)):
      return None
   # print(mrho.decode())
   return m#mByte.decode('utf-8')

   # m = 'im j5 dynamic jldajsfhajldajsfhasfhsdlfpjldaj \
# sfhasfhsdlfp9jldajsfhasfhsdlfp9uo58wghvlspthqoglsdjg\
# hshj4wtopestqwgwdsgsdfsgyewuo58wghvlspthqoglsdjghshj4\
# wtopestqwgwdsgsdfsgyew9uo58wghvlspthqoglsdjghshj4wtope\
# stqwgwdsgsdfsgyewsfhsdlfp9uo58wghvlspthqoglsdjghshj4wto\
# pestqwgwdsgsdfsgyew'
# j = 5
# # member starts from 0 .... n-1
# S = {1,2,0,4,6,7,8}
# print(f'I am party {j}')
# EncParty = (j,m,S)
# c5 = TSE.DistEnc(sk,EncParty,pp,t)
# #j = 3
# DecParty = (j,c5,S)
# p = TSE.DistDec(sk,DecParty,pp,t)
# print(p)
# # print(p==m)