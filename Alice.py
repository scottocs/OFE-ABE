# coding=utf-8

from charm.toolbox.pairinggroup import *
from utils.newsecretutils import Utils
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import re
# from newjson import ElementEncoder, ElementDecoder
import utils.newjson as newjson
import queue
import time
import threading
debug = False
import newma
import sys

class Alice:
    def __init__(self):
        self.groupObj = PairingGroup('SS512')
        self.dabe = newma.Dabe(self.groupObj)
        self.GP={}
        self.pks={}
        self.sks={}
        

        self.GP= newjson.loads(open("global_parameters.json","r").read())        
        self.n=self.GP["n"]
        self.t=int(self.n/2+1)
        self.pks=self.GP["pks"]
        self.sks= newjson.loads(open("secretKeys.json","r").read())                
        

    def send_ciphertext(self):
        m = self.groupObj.random(GT)
        nattributes = ["ATTR@AUTH"+str(j) for j in range(1, self.n+1)]
        policy = '(2 of (%d of (%s), ATTR@ALICE, ATTR@BOB))' % (self.n/2+1, ", ".join(nattributes))
        # print(policy)
        # print('Acces Control Policy: %s' % policy)
        print("There are %d TTPs" % self.n)
        ts=time.time()
        CT = self.dabe.encrypt(self.GP, self.pks, m, policy)
        # print("encryp time:",time.time()-ts)
        open("x.txt","w").write(newjson.dumps({"ct":CT,"m":m}))
        print('Alice\'s ciphertext has been written to x.txt')

    def verify_ciphertext(self):

        egg=pair(self.GP['g'],self.GP['g'])
        CT_BOB=newjson.loads(open("y.txt","r").read())["ct"]
        return self.dabe.isValid(CT_BOB, self.GP,self.GP["pks"])
        # return True

    def getDHKey(self):
        gt=eval(str(newjson.loads(open("x.txt","r").read())["m"]))
        D=newjson.loads(open("y.txt","r").read())["ct"]["D"]
        return (D**gt[0])**gt[1]
    
    def ElgamalEnc(self, K, pk):
        l=self.groupObj.random()
        # print(K["K"]pk**l)
        EK1=K["K"]* (pk**l)
        EK2=self.GP['g']**l
        EK3=K["KP"]
        return {"EK1":EK1,"EK2":EK2,"EK3":EK3}

    def ElgamalDec(self, EK, sk):        
        return {"K":EK["EK1"]/(EK["EK2"]**sk),"KP":EK["EK3"]}



    def send_decryptionkey(self):
        gid, abeKey = "EXid", {}
        abeKey["ALICE"] = self.dabe.keygen(self.GP, self.sks["ALICE"], gid, "ATTR@ALICE")

        encKey=self.ElgamalEnc(abeKey['ALICE'],self.pks["BOB"]["gz"])
        open("K_ALICE.txt","w").write(newjson.dumps(encKey))
        print("Alice sends decryption key using ElGamal encryption")
    
    def decrypt_CT(self):        
        decKey = {'GID': "EXid", 'keys': {}}
        BOBEK=newjson.loads(open("K_BOB.txt","r").read())        
        BOBK=self.ElgamalDec(BOBEK,self.sks["ALICE"]["z"])
        # print(BOBK)
        ALICEK = self.dabe.keygen(self.GP, self.sks["ALICE"], decKey["GID"], "ATTR@ALICE")
        
        decKey['keys']["ATTR@BOB"]=BOBK
        decKey['keys']["ATTR@ALICE"]=ALICEK
        CT_BOB=newjson.loads(open("y.txt","r").read())["ct"]
        m_BOB=newjson.loads(open("y.txt","r").read())["m"]

        y = self.dabe.decrypt(self.GP, decKey, CT_BOB)
        assert(y==m_BOB)
        return True

if __name__ == '__main__':
    # main(int(sys.argv[1]))

    print('Alice: Optimistic Fair Exchange of x')
    print()
    print('Commands:')
    print(' [1] Publish Ciphertext of secret x      [2] Verify ciphertext of y')    
    print(' [3] Transfer decryption key             [4] Decrypt the Ciphertext to get y')    

    print()
    alice = Alice()
    alice.n=int(sys.argv[1])
    while True:
        choice = int(input('Enter your choice: '))
        if choice == 1:
            alice.send_ciphertext()
        elif choice == 2:
            if alice.verify_ciphertext():
                print("Bob's ciphertext is correct")                
        elif choice == 3:
            alice.send_decryptionkey()            
        elif choice == 4:
            if alice.decrypt_CT():
                print("Alice obtains Bob's secret")
                break
        elif choice == 0:
            print('Quitting.\n')
            break
        else:
            print('Invalid choice. Valid chocices are 0 to 2.\n')
