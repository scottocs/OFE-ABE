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
        nattributes = ["ATTR"+str(j) for j in range(1, self.n+1)]
        policy = '(2 of (%d of (%s), ALICE, BOB))' % (self.n/2+1, ", ".join(nattributes))
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
        asserttime = {"C0":0,"C1":0,"C2":0,"C3":0}
        t1=time.time()
        assert(CT_BOB["C0p"] == CT_BOB["M1"]*(egg**CT_BOB["stilde"]) *(CT_BOB["C0"]**CT_BOB["cp"]))
        asserttime["C0"] = time.time() - t1
        
        t1=time.time()
        # print(Dp, gp['g']** M2, D** cp2)
        assert(CT_BOB["Dp"] == (self.GP['g']** CT_BOB["M2"]) * (CT_BOB["D"]** CT_BOB["cp2"]))
        asserttime["D"] = time.time() - t1
        policy = self.dabe.util.createPolicy(CT_BOB["policy"])
        
        # policy = self.dabe.util.createPolicy(policy_str)
        for attr, s_share in CT_BOB["secret_shareshat"].items():
            k_attr = self.dabe.util.strip_index(attr)
            t1 = time.time()
            assert(CT_BOB["C1p"][attr]==egg**CT_BOB["secret_shareshat"][attr] * self.GP["pks"][k_attr]['egga']**CT_BOB["rxhat"][attr]  * CT_BOB["C1"][attr]**CT_BOB["cp"])
            asserttime["C1"]+= time.time()-t1
            t1 = time.time()
            assert (CT_BOB["C2p"][attr] == self.GP['g'] ** CT_BOB["rxhat"][attr] * CT_BOB["C2"][attr] ** CT_BOB["cp"])
            asserttime["C2"] +=  time.time()-t1
            t1 = time.time()
            assert (CT_BOB["C3p"][attr] == self.GP["pks"][k_attr]['gy'] ** CT_BOB["rxhat"][attr] * self.GP['g'] **CT_BOB["zero_shareshat"][attr]  *CT_BOB["C3"][attr]**CT_BOB["cp"])
            asserttime["C3"] +=  time.time()-t1
        # print(asserttime)
        # allTime=0
        # for part in asserttime:
        #     allTime+=asserttime[part]
        # print(allTime)    
        return True

    def getDHKey(self):
        gt=eval(str(newjson.loads(open("x.txt","r").read())["m"]))
        D=newjson.loads(open("y.txt","r").read())["ct"]["D"]
        return (D**gt[0])**gt[1]

    def send_decryptionkey(self):
        gid, K = "EXid", {}
        self.dabe.keygen(self.GP, self.sks["ALICE"], "ALICE", gid, K)
        # TODO interestingly: g1**gt[0]**gt2[0] == g1**gt2[0]**gt[0]
        #               and   g1**gt[1]**gt2[1] == g1**gt2[1]**gt[1]
        # so DH exchange key is set as: g1**gt[0]**gt2[0]**gt[1]**gt2[1]
        # print(self.getDHKey())
        K['ALICE']['k'] = K['ALICE']['k']*self.getDHKey()

        open("K_ALICE.txt","w").write(newjson.dumps(K))
        print("Alice sends decryption key using DH exchange")
    
    def decrypt_CT(self):        
        K=newjson.loads(open("K_ALICE.txt","r").read())        
        K['ALICE']['k']=K['ALICE']['k']/self.getDHKey()
        BOBK=newjson.loads(open("K_BOB.txt","r").read())
        BOBK['BOB']['k']=BOBK['BOB']['k']/self.getDHKey()
        # print('BOB decryption Key:',BOBK['BOB']['k'])
        K.update(BOBK)        
        CT_BOB=newjson.loads(open("y.txt","r").read())["ct"]
        #this is used to compare
        m_BOB=newjson.loads(open("y.txt","r").read())["m"]
        y = self.dabe.decrypt(self.GP, K, CT_BOB)
        assert(y==m_BOB)
        return True

if __name__ == '__main__':
    # main(int(sys.argv[1]))

    print('Alice: Optimistic Fair Exchange of x')
    print()
    print('Commands:')
    print(' [1] Publish Ciphertext of secret x      [2] Verify ciphertext of y')    
    print(' [3] Transfer decryption key             [4] Decrypt the Ciphertext to get x')    

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
