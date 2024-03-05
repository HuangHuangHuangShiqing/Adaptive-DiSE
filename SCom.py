def Setupcom(k,g,p):
    '''
     setup the commitment
     parameter k: bit of p/secret parameter
     parameter g: generator of p
     parameter p: prime number
     return g, g^k % p
    '''
    h = pow(g,k,p)
    return g,h
    
def Com(m,ppCom,rho,p):
    '''
     commitment
     parameter m: mesage
     parameter p: modulus
     parameter ppCom: public parameter (g,h)
     parameter rho: randomness
     return (g^m * h^rho) % p
    '''
    g,h = ppCom
    return (pow(g,m,p) * pow(h,rho,p)) % p