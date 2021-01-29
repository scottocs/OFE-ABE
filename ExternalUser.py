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

class User:
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
        

    def verify_ciphertext(self, Ck, j):
        #verify the jth row of C0, C1, C2 or C3
        egg=pair(self.GP['g'],self.GP['g'])
        CT_BOB=newjson.loads(open("y.txt","r").read())["ct"]
        policy = self.dabe.util.createPolicy(CT_BOB["policy"])

        if Ck=="C0":
            assert(CT_BOB["C0p"] == CT_BOB["M1"]*(egg**CT_BOB["stilde"]) *(CT_BOB["C0"]**CT_BOB["cp"]))
        elif Ck in ["C1","C2","C3"]:
            for attr, s_share in CT_BOB["secret_shareshat"].items():
                if "ATTR%d"%j == attr:
                    k_attr = self.dabe.util.strip_index(attr)
                    if Ck=="C1":
                        assert(CT_BOB["C1p"][attr]==egg**CT_BOB["secret_shareshat"][attr] * self.GP["pks"][k_attr]['egga']**CT_BOB["rxhat"][attr]  * CT_BOB["C1"][attr]**CT_BOB["cp"])
                    if Ck=="C2":
                        assert (CT_BOB["C2p"][attr] == self.GP['g'] ** CT_BOB["rxhat"][attr] * CT_BOB["C2"][attr] ** CT_BOB["cp"])
                    if Ck=="C3":
                        assert (CT_BOB["C3p"][attr] == self.GP["pks"][k_attr]['gy'] ** CT_BOB["rxhat"][attr] * self.GP['g'] **CT_BOB["zero_shareshat"][attr]  *CT_BOB["C3"][attr]**CT_BOB["cp"])
                
        elif Ck =="D":
            assert(CT_BOB["Dp"] == (self.GP['g']** CT_BOB["M2"]) * (CT_BOB["D"]** CT_BOB["cp2"]))
        
        return True

    def verify_decryption_key(self):
        #verify an arbiter's decryption key        
        gid, K = "EXid", {}        
        self.dabe.keygen(self.GP, self.sks["ATTR1"], "ATTR1", gid, K)
        policy = '(ATTR1)'
        m = self.groupObj.random(GT)
        # print(policy)
        testCT = self.dabe.encrypt(self.GP, self.pks, m, policy)        
        mp = self.dabe.decrypt(self.GP, K, testCT)
        assert(m==mp)
        # print(policy)

        policy = '(ATTR2)' 
        testCT = self.dabe.encrypt(self.GP, self.pks, m, policy)        
        mp = self.dabe.decrypt(self.GP, K, testCT)
        assert(mp==None)
    
    def verify_Alice_Bob_decryption_key(self):
        #use pks, Alice and Bob's encrypted decryption keys to verify
        AliceK=newjson.loads(open("K_Alice.txt","r").read())["ALICE"]['k']
        BOBK=newjson.loads(open("K_BOB.txt","r").read())["BOB"]['k']
        gid, K = "EXid", {}
        h =  self.groupObj.hash(gid, G1)
        assert(pair(AliceK/BOBK,self.GP['g']) == 
            (self.pks["ALICE"]['egga']/self.pks["BOB"]['egga']) *
            (pair(h,self.pks["ALICE"]['gy'])/pair(h,self.pks["BOB"]['gy'])))


if __name__ == '__main__':
    # main(int(sys.argv[1]))

    print('All public information can be verified:')
    print()
    user = User()

    import random
    Ck=["C0","C1","C2","C3","D"][int(random.random()*5)]
    j=int(random.random()*user.n)
    user.verify_ciphertext(Ck, j)
    print("Verification of %dth row of %s: PASSED"%(j, Ck))
    print()
    
    user.verify_decryption_key()
    print("Verification of arbiter1's decryption: PASSED")
    print()
    
    user.verify_Alice_Bob_decryption_key()
    print("Verification of Alice and Bob's encrypted decryption keys: PASSED")
    print()

