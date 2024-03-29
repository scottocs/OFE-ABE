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
import setting,os

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
        self.H = lambda x: self.group.hash(x, G1)
        self.F = lambda x: self.group.hash(x, G1)
        
    def setup(self):
        g1 = self.group.random(G1)
        g2 = g1#self.group.random(G2)
        h = self.group.random(G1)
        egg = pair(g1, g2)
        gp = {'g':g1,'g1': g1,'h':h, 'g2': g2, 'egg': egg}
        if debug:
            print("Setup")
            print(gp)
        return gp

    def unpack_attribute(self, attribute):
        """
        Unpacks an attribute in attribute name, authority name and index
        :param attribute: The attribute to unpack
        :return: The attribute name, authority name and the attribute index, if present.

        >>> group = PairingGroup('SS512')
        >>> maabe = MaabeRW15(group)
        >>> maabe.unpack_attribute('STUDENT@UT')
        ('STUDENT', 'UT', None)
        >>> maabe.unpack_attribute('STUDENT@UT_2')
        ('STUDENT', 'UT', '2')
        """
        parts = re.split(r"[@_]", attribute)
        assert len(parts) > 1, "No @ char in [attribute@authority] name"
        return parts[0], parts[1], None if len(parts) < 3 else parts[2]

    def authsetup(self, gp, name):
        """
        Setup an attribute authority.
        :param gp: The global parameters
        :param name: The name of the authority
        :return: The public and private key of the authority
        """
        alpha, y = self.group.random(), self.group.random()
        sigy = self.group.random()
        z = self.group.random()
        egga = gp['egg'] ** alpha
        gy = gp['g'] ** y
        gz = gp['g'] ** z
        siggy = gp['g'] ** sigy
        pk = {'name': name, 'egga': egga, 'gy': gy, 'siggy':siggy, 'gz':gz}
        sk = {'name': name, 'alpha': alpha, 'y': y, 'sigy':sigy, 'z':z}
        if debug:
            print("Authsetup: %s" % name)
            print(pk)
            print(sk)

        return sk, pk

    def keygen(self, gp, sk, gid, attribute):
        """
        Generate a user secret key for the attribute.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attribute: The attribute.
        :return: The secret key for the attribute for the user with identifier gid.
        """
        _, auth, _ = self.unpack_attribute(attribute)
        # print(attribute,auth,sk)
        assert sk['name'] == auth, "Attribute %s does not belong to authority %s" % (attribute, sk['name'])

        t = self.group.random()
        K = gp['g2'] ** sk['alpha'] * self.H(gid) ** sk['y'] * self.F(attribute) ** t
        KP = gp['g1'] ** t
        if debug:
            print("Keygen")
            print("User: %s, Attribute: %s" % (gid, attribute))
            print({'K': K, 'KP': KP})
        return {'K': K, 'KP': KP}

    def multiple_attributes_keygen(self, gp, sk, gid, attributes):
        """
        Generate a dictionary of secret keys for a user for a list of attributes.
        :param gp: The global parameters.
        :param sk: The secret key of the attribute authority.
        :param gid: The global user identifier.
        :param attributes: The list of attributes.
        :return: A dictionary with attribute names as keys, and secret keys for the attributes as values.
        """
        uk = {}
        for attribute in attributes:
            uk[attribute] = self.keygen(gp, sk, gid, attribute)
        return uk

    def encrypt(self, gp, pks, m, policy_str):
        """
        Encrypt a message under an access policy
        :param gp: The global parameters.
        :param pks: The public keys of the relevant attribute authorities, as dict from authority name to public key.
        :param m: e(g,g)^m is to be encrypted.
        :param policy_str: The access policy to use.
        :return: The encrypted message.
        """
        s = self.group.random(ZR)  # secret to be shared
        sp = self.group.random(ZR)  # secret to be shared
        w = self.group.init(ZR, 0)  # 0 to be shared
        wp = 0

        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)

        secret_shares = self.util.calculateSharesDict(s, policy)  # These are correctly set to be exponents in Z_p
        zero_shares = self.util.calculateSharesDict(w, policy)

        secret_sharesp = self.util.calculateSharesDict(sp, policy)  # These are correctly set to be exponents in Z_p
        zero_sharesp = self.util.calculateSharesDict(wp, policy)
        M= gp['egg']**m
        C0 = [gp['g'],gp['g']**(m+s)]                 
        C5=gp['h']**s
        D=gp['h']**m
        C1, C2, C3, C4 = {}, {}, {}, {}
        C1p, C2p,C3p, C4p = {}, {}, {}, {}
        tx, txp = {}, {}
        

        mp=self.group.random(ZR)
        Mp=gp['egg']**mp
        C0p = [gp['g'],gp['g']**(mp+sp)] 
        C5p=gp['h']**sp
        Dp=gp['h']**mp
        curve_order =  self.group.order()
        cp = self.group.init(ZR,int(hash2(str(C0) + "||" + str(C1) + "||" + str(C2) + "||" + str(C3) + "||" + str(C4)), 16) )#% curve_order
        stilde = (sp - s*cp)# %curve_order  # for egg
        mtilde = (mp - m*cp)# %curve_order  # for egg
        asserttime = {"C0":0,"C1":0,"C2":0,"C3":0,"C4":0,"C5":0,"D":0,"pair":0}
        t1=time.time()
        assert(C0p[1] == (gp['g']**mtilde)*(gp['g']**stilde) *(C0[1]**cp))
        asserttime["C0"] = time.time() - t1
        t1 = time.time()
        assert(C5p == (gp['h']**stilde)*(C5**cp))
        asserttime["C5"] += time.time()-t1
        t1 = time.time()
        assert(Dp == (gp['h']**mtilde) *(D**cp))
        asserttime["D"] += time.time()-t1

        t1 = time.time()
        assert(pair(C0[1],gp['h']) == pair(C5*D, gp['g']))
        asserttime["pair"] += time.time()-t1


        txhat, secret_shareshat, zero_shareshat = {}, {}, {}

        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            tx[i] = self.group.random()
            C1[i] = gp['egg'] ** secret_shares[i] * pks[auth]['egga'] ** tx[i]
            C2[i] = gp['g1'] ** (-tx[i])
            C3[i] = pks[auth]['gy'] ** tx[i] * gp['g1'] ** zero_shares[i]
            C4[i] = self.F(attr) ** tx[i]

            txp[i] = self.group.random()
            C1p[i] = gp['egg'] ** secret_sharesp[i] * pks[auth]['egga'] ** txp[i]
            C2p[i] = gp['g1'] ** (-txp[i])
            C3p[i] = pks[auth]['gy'] ** txp[i] * gp['g1'] ** zero_sharesp[i]
            C4p[i] = self.F(attr) ** txp[i]

            txhat[i] = (txp[i] - cp * tx[i]) #% curve_order
            secret_shareshat[i] = (secret_sharesp[i] - cp * secret_shares[i]) #% curve_order
            zero_shareshat[i] = (zero_sharesp[i] - cp * zero_shares[i]) #% curve_order

            t1 = time.time()
            assert(C1p[i]==gp['egg']**secret_shareshat[i] * pks[auth]['egga']**txhat[i]  * C1[i]**cp)
            asserttime["C1"]+= time.time()-t1
            t1 = time.time()
            assert (C2p[i] == gp['g1'] ** (-txhat[i]) * C2[i] ** cp)
            asserttime["C2"] +=  time.time()-t1
            t1 = time.time()
            assert (C3p[i] == pks[auth]['gy'] ** txhat[i] * gp['g1'] **zero_shareshat[i]  *C3[i]**cp)
            asserttime["C3"] +=  time.time()-t1
            t1 = time.time()
            assert (C4p[i] == self.F(attr) ** txhat[i] * C4[i] ** cp)
            asserttime["C4"] += time.time()-t1



        print("asserttime",asserttime)
        # c = self.group.init(ZR,int(hash(str(C0) + "||" + str(C1) + "||" + str(C2) + "||" + str(C3) + "||" + str(C4)), 16))# % curve_order

        if debug:
            print("Encrypt")
            print(message)
            print({'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4})
        # return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}

        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4,'C5':C5,'D':D,\
         'C0p': C0p, 'C1p': C1p, 'C2p': C2p, 'C3p': C3p,'C4p': C4p,'C5p':C5p,'Dp':Dp, \
         "txhat": txhat,
         "secret_shareshat": secret_shareshat,
         "zero_shareshat": zero_shareshat,
         "cp": cp,
         "stilde": stilde,
         "mtilde": mtilde,
         }
    def divideCT(self, ct1, ct2):
        ct={}
        policy_str=ct1['policy']
        if ct1['policy'] != ct2['policy']:
            print("policy not equal!! cannot divide")
            return
        C0 = ct1['C0']/ct2['C0']
        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)


        C1, C2, C3, C4 = {}, {}, {}, {}
        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            C1[i] = ct1['C1'][i]/ct2['C1'][i]
            C2[i] = ct1['C2'][i]/ct2['C2'][i]
            C3[i] = ct1['C3'][i]/ct2['C3'][i]
            C4[i] = ct1['C4'][i]/ct2['C4'][i]
        return {'policy': policy_str, 'C0': C0, 'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4}
    def isValid(self, com, gp, pks):
        C0p = com["C0p"]
        mtilde = com["mtilde"]
        policy_str = com["policy"]
        stilde = com["stilde"]
        C0 = com["C0"]
        C5 = com["C5"]
        D = com["D"]
        cp = com["cp"]
        C1p = com["C1p"]
        secret_shareshat = com["secret_shareshat"]
        txhat = com["txhat"]
        C1 = com["C1"]
        C2 = com["C2"]
        C2p = com["C2p"]
        C3p = com["C3p"]
        zero_shareshat = com["zero_shareshat"]
        C3 = com["C3"]
        C4 = com["C4"]
        C4p = com["C4p"]
        C5p = com["C5p"]
        Dp = com["Dp"]

        policy = self.util.createPolicy(policy_str)
        attribute_list = self.util.getAttributeList(policy)

        asserttime = {"C0": 0, "C1": 0, "C2": 0, "C3": 0, "C4": 0,"C5": 0,"D": 0,"Hash":0,"all":0}
        ts=time.time()
        t1=time.time()
        # assert (C0p == Mtilde * (gp['egg'] ** stilde) * (C0 ** cp))
        assert(C0p[1] == (gp['g']**mtilde)*(gp['g']**stilde) *(C0[1]**cp))
        asserttime["C0"] = time.time()-t1

        t1 = time.time()
        assert(C5p == (gp['h']**stilde)*(C5**cp))
        asserttime["C5"] += time.time()-t1
        t1 = time.time()
        assert(Dp == (gp['h']**mtilde) *(D**cp))
        asserttime["D"] += time.time()-t1


        for i in attribute_list:
            attribute_name, auth, _ = self.unpack_attribute(i)
            attr = "%s@%s" % (attribute_name, auth)
            t1=time.time()
            assert(C1p[i]==gp['egg']**secret_shareshat[i] * pks[auth]['egga']**txhat[i]  * C1[i]**cp)
            asserttime["C1"] += time.time() - t1
            t1 = time.time()
            assert (C2p[i] == gp['g1'] ** (-txhat[i]) * C2[i] ** cp)
            asserttime["C2"] += time.time() - t1
            t1 = time.time()
            assert (C3p[i] == pks[auth]['gy'] ** txhat[i] * gp['g1'] **zero_shareshat[i]  *C3[i]**cp)
            asserttime["C3"] += time.time() - t1
            t1 = time.time()
            hashv=self.F(attr)
            asserttime["Hash"] += time.time() - t1
            assert (C4p[i] == hashv ** txhat[i] * C4[i] ** cp)
            asserttime["C4"] += time.time() - t1

        asserttime["all"]= time.time() - ts
        print("asserttime",asserttime)
        return True
    def decrypt(self, gp, sk, ct):
        """
        Decrypt the ciphertext using the secret keys of the user.
        :param gp: The global parameters.
        :param sk: The secret keys of the user.
        :param ct: The ciphertext to decrypt.
        :return: The decrypted message.
        :raise Exception: When the access policy can not be satisfied with the user's attributes.
        """
        policy = self.util.createPolicy(ct['policy'])
        # coefficients = self.util.newGetCoefficients(policy)
        pruned_list = self.util.prune(policy, sk['keys'].keys())
        coefficients = self.util.newGetCoefficients(policy, pruned_list)

        if not pruned_list:
            raise Exception("You don't have the required attributes for decryption!")

        B = self.group.init(GT, 1)
        for i in range(len(pruned_list)):
            x = pruned_list[i].getAttribute()  # without the underscore
            y = pruned_list[i].getAttributeAndIndex()  # with the underscore
            B *= (ct['C1'][y] * pair(ct['C2'][y], sk['keys'][x]['K']) * pair(ct['C3'][y], self.H(sk['GID'])) * pair(
                sk['keys'][x]['KP'], ct['C4'][y])) ** coefficients[y]
        if debug:
            print("Decrypt")
            print("SK:")
            print(sk)
            print("Decrypted Message:")
            print(pair(ct['C0'][0],ct['C0'][1]) / B)
        return pair(ct['C0'][0],ct['C0'][1])/B

def main(n,t,res={"C0":[],"C1":[],"C2":[],"C3":[],"D":[]}):
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
    # t=int(n/2+1)

    # GP = dabe.setup()   
    os.system("rm -rf global_parameters.json")
    try:
        GP= newjson.loads(open("global_parameters.json","r").read())        
        pks=GP["pks"]
        sks= newjson.loads(open("secretKeys.json","r").read())                
    except Exception as e:
        GP = dabe.setup()   
        #Setup n authorities
        for i in range(1,n+1):
            node='AUTH'+str(i)
            # auth_attrs=[attr]
            (SK, PK) = dabe.authsetup(GP, node)
            pks[node]=PK
            sks[node]=SK
        (SK, PK) = dabe.authsetup(GP, "ALICE")
        pks["ALICE"]=PK
        sks["ALICE"]=SK

        (SK, PK) = dabe.authsetup(GP, "BOB")
        pks["BOB"]=PK
        sks["BOB"]=SK

        GP["g"]=GP["g"]
        GP["n"]=n
        GP['pks']=pks
        open("global_parameters.json","w").write(newjson.dumps(GP))        
        open("secretKeys.json","w").write(newjson.dumps(sks))        
    
    
    # print(sks)
    #Setup a user and give him some keys
    decKey = {'GID': "EXid", 'keys': {}}
    # gid, K = "EXid", {}
    nodes = ['AUTH'+str(i) for i in range(1,t+1)]
    for node in nodes: 
        # ts=time.time()
        # print(sks[i])
        user_keys1 = dabe.multiple_attributes_keygen(GP, sks[node], decKey['GID'], ["ATTR@"+node]) 
        decKey["keys"].update(user_keys1)

    if debug: print('User credential list: %s' % nodes)
    if debug: print("\nSecret key:")
    if debug: groupObj.debug(K)

    #Encrypt a random element in GT
    m = groupObj.random(ZR)
    # policy = '(2 of (ATTR1, ATTR2, ATTR4))'#'((ATTR1 or ATTR3) and (ATTR2 or ATTR4))'
    nattributes = ["ATTR@AUTH"+str(j) for j in range(1, n+1)]
    policy = '(%d of (%s))' % (t, ", ".join(nattributes))
    # print(policy)
    if debug: print('Acces Policy: %s' % policy)
    CT = dabe.encrypt(GP, pks, m, policy)
    
    oriCT={}
    for item in ['policy','C0','C1','C2','C3']:
        oriCT[item]=CT[item]

    # print("MSG size",len(newjson.dumps(CT))/1024., "CT size",len(newjson.dumps(oriCT))/1024.)
    if debug: print("\nCiphertext...")
    if debug: groupObj.debug(CT)
    # ts=time.time()
    orig_m = dabe.decrypt(GP, decKey, CT)
    # print("decryption time",time.time()-ts)

    assert GP["egg"]**m == orig_m, 'FAILED Decryption!!!'
    print('Successful Decryption!')
    return 

def getRandom(n):
    import random
    return int(random.random()*n)
    # return p
# def commitDescription():
#     groupObj = PairingGroup('SS512')

#     starttime=time.time()
#     for i in range(0,100):
#         pair(groupObj.random(G1),groupObj.random(G2))
#     print("pairing time cost:",time.time()-starttime)

#     starttime=time.time()
#     for i in range(0,100):
#         groupObj.random(G1)** groupObj.random(ZR)
#     print("exponentiation time cost:",time.time()-starttime)
    
#     gp={
#         "g":groupObj.random(G1),
#         "h":groupObj.random(G1)
#     }
#     dabe = Dabe(groupObj)
#     m=groupObj.random()
#     M=groupObj.random(GT)
#     Mp=groupObj.random(GT)
    
#     curve_order =  groupObj.order()
#     from gmpy2 import c_mod, mpz,mul
    

#     # print(curve_order)
#     for i in range(0, len(eval(str(Mp)))):            
#         #different with BN128: curve_order -> (FQ) field_modulus-1        
#         Mpv=eval(str(Mp))[i]%curve_order
#         Mv=eval(str(M))[i]%curve_order
#         cp2 = eval(str(groupObj.init(ZR,int(hash2(str(M) + "||" + str(Mp) ), 16) )))% curve_order
        
#         D=gp['g']**Mv
#         Dp=gp['g']**Mpv
#         M2=(Mpv-cp2*Mv) % curve_order
#         assert(Dp == (gp['g']** M2) * (D** cp2))
                
#         print("calculation of h^M["+str(i)+"] true, where h in G1, M in GT")
#     # print(c,type(c))
#     # print(Mp/M)
#     # d=mpz(eval(str(Mhat))[0])
#     # d=eval(str(d))
#     # print(d,type(d))
    
    


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
    # commitDescription()
    N = setting.N
    t=setting.t

    main(N,t)
