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
import sys

import hashlib
def hash(str):
    x = hashlib.sha256()
    x.update(str.encode())
    return x.hexdigest()

def hash2(str):
    x = hashlib.sha256()
    x.update((str+"2").encode())
    return x.hexdigest()


class Dabe(ABEncMultiAuth):

    def __init__(self, group, verbose=False):
        ABEncMultiAuth.__init__(self)
        
        self.group = group
        self.util = Utils(group, verbose)

    def setup(self):

        g = self.group.random(G1)
        #: The oracle that maps global identities GID onto elements of G
        #:H = lambda str: g** group.hash(str)        
        GP = {'g':g}
        
        return GP

    def authsetup(self, GP, attributes):
        egg=pair(GP['g'],GP['g'])

        #For each attribute i belonging to the authority, the authority chooses two random exponents, 
        #alpha_i, y_i and publishes PK={e(g,g)^alpha_i, g^y_i} for each attribute 
        #it keeps SK = {alpha_i, y_i} as its secret key
        SK = {} #dictionary of {s: {alpha, y}} 
        PK = {} #dictionary of {s: {e(g,g)^alpha, g^y}}
        for i in attributes:
            #TODO: Is ZR an appropriate choice for a random element in Zp?
            alpha, y = self.group.random(), self.group.random()
            e_gg_alpha = egg ** alpha
            g_y = GP['g'] ** y
            SK[i.upper()] = {'alpha': alpha, 'y': y}
            PK[i.upper()] = {'egga': e_gg_alpha, 'gy': g_y}
        # print(PK)
             
        return (SK, PK)


    def keygen(self, gp, sk, i, gid, pkey):
        '''Create a key for GID on attribute i belonging to authority sk
        sk is the private key for the releveant authority
        i is the attribute to give bob
        pkey is bob's private key dictionary, to which the appropriate private key is added
        '''
        #To create a key for GID for attribute i belonging to an authority, the authority computes K_{i,GID} = g^alpha * H(GID)^y_
        h = self.group.hash(gid, G1)
        K = (gp['g'] ** sk[i.upper()]['alpha']) * (h ** sk[i.upper()]['y'])
        
        pkey[i.upper()] = {'k': K}
        pkey['gid'] = gid
        
        if(debug):
            print("Key gen for %s on %s" % (gid, i))
            print("H(GID): '%s'" % h)
            print("K = g^alpha * H(GID) ^ y: %s" % K)
        return None

    def encrypt(self, gp, pk, M, policy_str,res={"C0":[],"C1":[],"C2":[],"C3":[],"D":[]}):
        egg=pair(gp['g'],gp['g'])
        s = self.group.random()
        sp = self.group.random()  # secret to be shared
        w = self.group.init(ZR, 0)
        wp = self.group.init(ZR, 0)
        egg_s = egg ** s
        C0 = M * egg_s
        C1, C2, C3 = {}, {}, {}
        C1p, C2p,C3p = {}, {}, {}
        rx, rxp = {}, {}
        rxhat, secret_shareshat, zero_shareshat = {}, {}, {}

        Mp=self.group.random(GT)
        C0p = Mp  * (egg ** sp)
        curve_order =  self.group.order()
        cp = self.group.init(ZR,int(hash(str(C0) + "||" + str(C1) + "||" + str(C2) + "||" + str(C3) ), 16) )#% curve_order
        cp2 = self.group.init(ZR,int(hash2(str(C0) + "||" + str(C1) + "||" + str(C2) + "||" + str(C3) ), 16) )#% curve_order
        stilde = (sp - s*cp)# %curve_order  # for egg
        M1 = Mp/(M**cp)
        
        # γ(M)-> Z_p^2
        Mpv=eval(str(Mp))[0]
        Mv=eval(str(M))[0]

        Mpv=eval(str(Mp))[1]
        Mv=eval(str(M))[1]

        from gmpy2 import c_mod, mpz,mul
        # γ(M)-> Z_p^1
        # Mpv=mpz(eval(str(Mp))[0])*mpz(eval(str(Mp))[1])
        # Mv=mpz(eval(str(M))[0])*mpz(eval(str(M))[1])
        
        D=gp['g']**eval(str(Mv))
        # print(D, (gp['g']**eval(str(M))[0]) ** eval(str(M))[1])
        Dp=gp['g']**eval(str(Mpv))
        # print(int(curve_order))
        
        M2= mpz(str(curve_order)) + c_mod(mpz(Mpv)- mul(mpz(Mv),mpz(str(cp2))), mpz(str(curve_order)))
        M2=eval(str(M2))
        # asserttime = {"C0":0,"C1":0,"C2":0,"C3":0}
        # t1=time.time()
        # assert(C0p == M1*(egg**stilde) *(C0**cp))
        # asserttime["C0"] = time.time() - t1
        # res["C0"].append(asserttime["C0"])
        # t1=time.time()
        # print(Dp, gp['g']** M2, D** cp2)
        assert(Dp == (gp['g']** M2) * (D** cp2))
        # print("assert passed")
        # asserttime["D"] = time.time() - t1
        # res["D"].append(asserttime["D"])
        
        #Parse the policy string into a tree
        policy = self.util.createPolicy(policy_str)
        sshares = self.util.calculateSharesList(s, policy) #Shares of the secret 
        wshares = self.util.calculateSharesList(w, policy) #Shares of 0        
        wshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in wshares])
        sshares = dict([(x[0].getAttributeAndIndex(), x[1]) for x in sshares])

        ssharesp = self.util.calculateSharesList(s, policy) #Shares of the secret 
        wsharesp = self.util.calculateSharesList(w, policy) #Shares of 0        
        wsharesp = dict([(x[0].getAttributeAndIndex(), x[1]) for x in wsharesp])
        ssharesp = dict([(x[0].getAttributeAndIndex(), x[1]) for x in ssharesp])
        

        for attr, s_share in sshares.items():
            k_attr = self.util.strip_index(attr)
            # print("===",k_attr,attr,pk)
            w_share = wshares[attr]
            rx[attr] = self.group.random()
            C1[attr] = (egg ** s_share) * (pk[k_attr]['egga'] ** rx[attr])
            C2[attr] = gp['g'] ** rx[attr]
            C3[attr] = (pk[k_attr]['gy'] ** rx[attr]) * (gp['g'] ** w_share)

            w_sharep = wsharesp[attr]
            s_sharep = ssharesp[attr]
            rxp[attr] = self.group.random()
            C1p[attr] = (egg** s_sharep) * (pk[k_attr]['egga'] ** rxp[attr])
            C2p[attr] = gp['g'] ** rxp[attr]
            C3p[attr] = (pk[k_attr]['gy'] ** rxp[attr]) * (gp['g'] ** w_sharep)
            
            rxhat[attr] = (rxp[attr] - cp * rx[attr]) #% curve_order
            secret_shareshat[attr] = (ssharesp[attr] - cp * sshares[attr]) #% curve_order
            zero_shareshat[attr] = (wsharesp[attr] - cp * wshares[attr]) #% curve_order

            # t1 = time.time()
            # assert(C1p[attr]==egg**secret_shareshat[attr] * pk[k_attr]['egga']**rxhat[attr]  * C1[attr]**cp)
            # asserttime["C1"]+= time.time()-t1
            # t1 = time.time()
            # assert (C2p[attr] == gp['g'] ** rxhat[attr] * C2[attr] ** cp)
            # asserttime["C2"] +=  time.time()-t1
            # t1 = time.time()
            # assert (C3p[attr] == pk[k_attr]['gy'] ** rxhat[attr] * gp['g'] **zero_shareshat[attr]  *C3[attr]**cp)
            # asserttime["C3"] +=  time.time()-t1
        # res["C1"].append(asserttime["C1"])
        # res["C2"].append(asserttime["C2"])
        # res["C3"].append(asserttime["C3"])
        # print(asserttime)

        if debug:
            print("Encrypt")
            print(M)
            print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3})
        

        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'D':D,\
         'C0p': C0p, 'C1p': C1p, 'C2p': C2p, 'C3p': C3p,'Dp':Dp,\
         "rxhat": rxhat,
         "secret_shareshat": secret_shareshat,
         "zero_shareshat": zero_shareshat,
         "cp": cp,
         "cp2": cp2,
         "stilde": stilde,
         "M1": M1,
         'M2': M2,
         }
    
    def isValid(self, com, gp, pks):
        C0p = com["C0p"]
        M1 = com["M1"]
        policy_str = com["policy"]
        stilde = com["stilde"]
        C0 = com["C0"]
        cp = com["cp"]
        C1p = com["C1p"]
        secret_shareshat = com["secret_shareshat"]
        rxhat = com["rxhat"]
        C1 = com["C1"]
        C2 = com["C2"]
        C2p = com["C2p"]
        C3p = com["C3p"]
        zero_shareshat = com["zero_shareshat"]
        C3 = com["C3"]

        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)

        asserttime = {"C0": 0, "C1": 0, "C2": 0, "C3": 0,"Hash":0}
        t1=time.time()
        assert (C0p == M1 * (gp['egg'] ** stilde) * (C0 ** cp))
        asserttime["C0"] = time.time()-t1
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            t1=time.time()
            assert(C1p[attr]==gp['egg']**secret_shareshat[attr] * pks[auth]['egga']**rxhat[attr]  * C1[attr]**cp)
            asserttime["C1"] += time.time() - t1
            t1 = time.time()
            assert (C2p[attr] == gp['g'] ** (rxhat[attr]) * C2[attr] ** cp)
            asserttime["C2"] += time.time() - t1
            t1 = time.time()
            assert (C3p[attr] == pks[auth]['gy'] ** rxhat[attr] * gp['g'] **zero_shareshat[attr]  *C3[attr]**cp)
            asserttime["C3"] += time.time() - t1
            t1 = time.time()
            hashv=gp['F'](attr)
            asserttime["Hash"] += time.time() - t1
            

        # print("asserttime",asserttime)
        return True

    def decrypt(self, gp, sk, ct):
        '''Decrypt a ciphertext
        SK is the user's private key dictionary {attr: { xxx , xxx }}
        ''' 
        usr_attribs = list(sk.keys())
        usr_attribs.remove('gid')
        policy = self.util.createPolicy(ct['policy'])
        pruned = self.util.prune(policy, usr_attribs)
        coeffs = self.util.newGetCoefficients(policy, pruned)
        
    
        h_gid = self.group.hash(sk['gid'],G1)  #find H(GID)
        egg_s = 1
        # print(type(pruned))
        if str(type(pruned)) == "<class 'bool'>" :
            return None

        for i in pruned:
            x = i.getAttributeAndIndex()
            y = i.getAttribute()
            num = ct['C1'][x] * pair(h_gid, ct['C3'][x])
            dem = pair(sk[y]['k'], ct['C2'][x])
            egg_s *= ( (num / dem) ** coeffs[x] )
   
        if(debug): print("e(gg)^s: %s" % egg_s)

        return ct['C0'] / egg_s


def main(n,res={"C0":[],"C1":[],"C2":[],"C3":[],"D":[]}):
    groupObj = PairingGroup('SS512')

    dabe = Dabe(groupObj)
    g1=groupObj.random(G1)
    g1p=groupObj.random(G1)
    m=groupObj.random()
    # ts=time.time()
    # x=g1*g1p
    # print("multiply G1 time", time.time()-ts)
    # ts=time.time()
    # x=g1**m
    # print("exponention G1 time", time.time()-ts)
    # g2=groupObj.random(G2)
    # g2p=groupObj.random(G2)
    # ts=time.time()
    # x=g2*g2p
    # print("multiply G2 time", time.time()-ts)
    # ts=time.time()
    # x=g2**m
    # print("exponention G2 time", time.time()-ts)

    # gt=groupObj.random(GT)
    # gtp=groupObj.random(GT)
    # ts=time.time()
    # x=gt*gtp
    # print("multiply GT time", time.time()-ts)
    # ts=time.time()
    # x=gt**m
    # print("exponention GT time", time.time()-ts)

    # ts=time.time()    
    # gt=pair(g1,g2)#
    # print("pairing time", time.time()-ts)    

    # print(g1, g2, gt)
    # gt=groupObj.random(GT)
    # gt2=groupObj.random(GT)
    # print(eval(str(gt)))
    # print(eval(str(g1)))
    # print(groupObj.order())
    # print("g1**gt[0]**gt2[0]",(g1**(eval(str(gt))[0]))** (eval(str(gt2))[0]))    
    # print("g1**gt[0]**gt2[0]",(g1**(eval(str(gt2))[0]))** (eval(str(gt))[0]))
    # print("g1**gt[1]**gt2[1]",(g2**(eval(str(gt))[1]))** (eval(str(gt2))[1]))
    # print("g1**gt[1]**gt2[1]",(g2**(eval(str(gt2))[1]))** (eval(str(gt))[1]))
    # print("g1**gt[1]",g1**eval(str(gt))[1])
    # exit()
    GP={}
    pks={}
    sks={}
    t=int(n/2+1)

    # GP = dabe.setup()   
    try:
        GP= newjson.loads(open("global_parameters.json","r").read())        
        pks=GP["pks"]
        sks= newjson.loads(open("secretKeys.json","r").read())                
    except Exception as e:
        GP = dabe.setup()   
        #Setup n authorities
        for i in range(1,n+1):
            attr='ATTR'+str(i)
            auth_attrs=[attr]
            (SK, PK) = dabe.authsetup(GP, auth_attrs)
            pks[attr]=PK[attr]
            sks[attr]=SK
        (SK, PK) = dabe.authsetup(GP, ["ALICE"])
        pks["ALICE"]=PK["ALICE"]
        sks["ALICE"]=SK

        (SK, PK) = dabe.authsetup(GP, ["BOB"])
        pks["BOB"]=PK["BOB"]
        sks["BOB"]=SK

        GP["g"]=GP["g"]
        GP["n"]=n
        GP['pks']=pks
        open("global_parameters.json","w").write(newjson.dumps(GP))        
        open("secretKeys.json","w").write(newjson.dumps(sks))        
    
    
    # print(sks)
    #Setup a user and give him some keys
    gid, K = "bob", {}
    usr_attrs = ['ATTR'+str(i) for i in range(1,t+1)]
    for i in usr_attrs: 
        # ts=time.time()
        dabe.keygen(GP, sks[i], i, gid, K)
        # print("keygen time",time.time()-ts)

    if debug: print('User credential list: %s' % usr_attrs)
    if debug: print("\nSecret key:")
    if debug: groupObj.debug(K)

    #Encrypt a random element in GT
    m = groupObj.random(GT)
    # policy = '(2 of (ATTR1, ATTR2, ATTR4))'#'((ATTR1 or ATTR3) and (ATTR2 or ATTR4))'
    nattributes = ["ATTR"+str(j) for j in range(1, n+1)]
    policy = '(%d of (%s))' % (t, ", ".join(nattributes))
    # print(policy)
    if debug: print('Acces Policy: %s' % policy)
    CT = dabe.encrypt(GP, pks, m, policy,res)
    
    oriCT={}
    for item in ['policy','C0','C1','C2','C3']:
        oriCT[item]=CT[item]

    # print("MSG size",len(newjson.dumps(CT))/1024., "CT size",len(newjson.dumps(oriCT))/1024.)
    if debug: print("\nCiphertext...")
    if debug: groupObj.debug(CT)
    # ts=time.time()
    orig_m = dabe.decrypt(GP, K, CT)
    # print("decryption time",time.time()-ts)

    assert m == orig_m, 'FAILED Decryption!!!'
    print('Successful Decryption!')
    return 

if __name__ == '__main__':
    # debug = False
    # priRes={"C0":[],"C1":[],"C2":[],"C3":[],"D":[]}
    # times=30
    # for n in range(10,110,10):
    #     res={"C0":[],"C1":[],"C2":[],"C3":[],"D":[]}
    #     print("n=",n,"times=",times)
    #     for j in range(0,times):        
    #         main(n,res)
    #     for item in res:
    #         # print(item,sum(res[item])/len(res[item]))
    #         priRes[item].append((n,sum(res[item])/len(res[item])))
    # print(priRes)
    main(int(sys.argv[1]),)
