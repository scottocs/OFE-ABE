# coding=utf-8

from charm.toolbox.pairinggroup import *
from newsecretutils import Utils
from charm.toolbox.ABEncMultiAuth import ABEncMultiAuth
import re
# from newjson import ElementEncoder, ElementDecoder
import newjson
import queue
import time
import threading
debug = False
import newma
import sys

class Bob:
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
        # print('Access Control Policy: %s' % policy)
        print("There are %d TTPs" % self.n)
        CT = self.dabe.encrypt(self.GP, self.pks, m, policy)
        open("y.txt","w").write(newjson.dumps({"ct":CT,"m":m}))
        print('Bob\'s ciphertext has been written to y.txt')

    def verify_ciphertext(self):
        egg=pair(self.GP['g'],self.GP['g'])
        CT_ALICE=newjson.loads(open("x.txt","r").read())["ct"]
        asserttime = {"C0":0,"C1":0,"C2":0,"C3":0}
        t1=time.time()
        assert(CT_ALICE["C0p"] == CT_ALICE["M1"]*(egg**CT_ALICE["stilde"]) *(CT_ALICE["C0"]**CT_ALICE["cp"]))
        asserttime["C0"] = time.time() - t1
        
        t1=time.time()
        # print(Dp, gp['g']** M2, D** cp2)
        assert(CT_ALICE["Dp"] == (self.GP['g']** CT_ALICE["M2"]) * (CT_ALICE["D"]** CT_ALICE["cp2"]))
        asserttime["D"] = time.time() - t1
        policy = self.dabe.util.createPolicy(CT_ALICE["policy"])
        
        # policy = self.dabe.util.createPolicy(policy_str)
        for attr, s_share in CT_ALICE["secret_shareshat"].items():
            k_attr = self.dabe.util.strip_index(attr)
            t1 = time.time()
            assert(CT_ALICE["C1p"][attr]==egg**CT_ALICE["secret_shareshat"][attr] * self.GP["pks"][k_attr]['egga']**CT_ALICE["rxhat"][attr]  * CT_ALICE["C1"][attr]**CT_ALICE["cp"])
            asserttime["C1"]+= time.time()-t1
            t1 = time.time()
            assert (CT_ALICE["C2p"][attr] == self.GP['g'] ** CT_ALICE["rxhat"][attr] * CT_ALICE["C2"][attr] ** CT_ALICE["cp"])
            asserttime["C2"] +=  time.time()-t1
            t1 = time.time()
            assert (CT_ALICE["C3p"][attr] == self.GP["pks"][k_attr]['gy'] ** CT_ALICE["rxhat"][attr] * self.GP['g'] **CT_ALICE["zero_shareshat"][attr]  *CT_ALICE["C3"][attr]**CT_ALICE["cp"])
            asserttime["C3"] +=  time.time()-t1
        # print(asserttime)
        # allTime=0
        # for part in asserttime:
        #     allTime+=asserttime[part]
        # print(allTime)
        return True



    def getDHKey(self):
        gt=eval(str(newjson.loads(open("y.txt","r").read())["m"]))
        D=newjson.loads(open("x.txt","r").read())["ct"]["D"]
        return (D**gt[0])**gt[1]


    def send_decryptionkey(self):
        gid, K = "EXid", {}
        self.dabe.keygen(self.GP, self.sks["BOB"], "BOB", gid, K)
        # print(self.getDHKey())
        # print('BOB generate Key:',K['BOB']['k'])
        K['BOB']['k'] = K['BOB']['k']*self.getDHKey()
        open("K_BOB.txt","w").write(newjson.dumps(K))
        print("Bob sends decryption key using DH exchange")
    
    def decrypt_CT(self):
        K=newjson.loads(open("K_BOB.txt","r").read())    
        K['BOB']['k']=K['BOB']['k']/self.getDHKey()    
        ALICEK=newjson.loads(open("K_ALICE.txt","r").read())
        ALICEK['ALICE']['k']=ALICEK['ALICE']['k']/self.getDHKey()

        K.update(ALICEK)
        CT_ALICE=newjson.loads(open("x.txt","r").read())["ct"]
        m_ALICE=newjson.loads(open("x.txt","r").read())["m"]
        x = self.dabe.decrypt(self.GP, K, CT_ALICE)
        assert(x==m_ALICE)
        return True

if __name__ == '__main__':
    # main(int(sys.argv[1]))

    print('Bob: Optimistic Fair Exchange of y')
    print()
    print('Commands:')
    print(' [1] Publish Ciphertext of secret y       [2] Verify ciphertext of x')    
    print(' [3] Transfer decryption key              [4] Decrypt the Ciphertext to get y')    

    print()
    bob = Bob()
    while True:
        choice = int(input('Enter your choice: '))
        if choice == 1:
            bob.send_ciphertext()
        elif choice == 2:
            if bob.verify_ciphertext():
                print("Alice's ciphertext is correct")                
        elif choice == 3:
            bob.send_decryptionkey()            
        elif choice == 4:
            if bob.decrypt_CT():
                print("Bob obtains Alice's secret")
                break
        elif choice == 0:
            print('Quitting.\n')
            break
        else:
            print('Invalid choice. Valid chocices are 0 to 2.\n')
