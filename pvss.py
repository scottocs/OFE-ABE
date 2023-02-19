from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from utils.newsecretutils import Utils
import utils.newjson as newjson
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random
import time,sys
import setting



N = setting.N
t=setting.t


class SCHPVSS():
    def dleq(self, g, y1, pks, y2, shares):
        """ DLEQ... discrete logarithm equality
        Proofs that the caller knows alpha such that y1[i] = x1[i]**alpha and y2[i] = x2[i]**alpha
        without revealing alpha.
        """
        w = self.group.random(ZR)
        z=[0 for i in range(0,len(y1))]
        a1=[0 for i in range(0,len(y1))]
        a2=[0 for i in range(0,len(y1))]
        c = self.group.hash(str(y1)+str(y2), ZR)
        
        for i in range(1, len(z)):
            a1[i] = g**w
            a2[i] = pks[i]**w        
            z[i] = w - shares[i] * c    
        
        return {"g":g, "y1":y1, "pks":pks, "y2":y2, "c":c, "a1":a1, "a2":a2, "z":z}


    def dleq_verify(self, g, y1, pks, y2, c, a1, a2, z):
        for i in range(1, N+1):
            if a1[i] != (g**z[i]) * (y1[i]**c):# or a2 !=pks** z[i] * y2[i] **c:
                return False
        return True



    # setup()
    def __init__(self, groupObj):        
        global util, group
        self.util = Utils(groupObj, verbose=False)
        self.group = groupObj
        
        self.g, self.gp = self.group.random(G1), self.group.random(G2)
        # self.g.initPP(); gp.initPP()
        
        # shareholders are in [1, N]
        self.sks=[self.group.random(ZR) for i in range(0,N+1)]
        self.pks=[self.gp**self.sks[i] for i in range(0,N+1)]

           
    def distribute(self):
        s=self.group.random(ZR)
        self.S=self.gp**s

        shares, para = self.util.genShares2(s, t, N)
        # print(para)
        Cj=[]
        for paraj in para:
            Cj.append(self.g** paraj)

        Yi=[0]
        Yi.extend([self.pks[i]** shares[i] for i in range(1, N+1)])
        Xi=[0]        
        for i in range(1, N+1):
            tmp=1
            # self.group.init(G1,1)
            for j in range(0, t):
                tmp=tmp* (Cj[j]** (i**j))
            Xi.append(tmp)

        dleqproofs=self.dleq(self.g, Xi,self.pks,Yi, shares)

        
        res={"Cj":Cj}
        res.update(dleqproofs)
        
        print("dis message size:",len(str(res)))
        return res


    def verify(self, dis):
        starttime = time.time()
        Cj=dis['Cj']
        Xi=[0]        
        for i in range(1, N+1):
            tmp=1
            # self.group.init(G1,1)
            for j in range(0, t):
                tmp=tmp* (Cj[j]** (i**j))
            Xi.append(tmp)

        
        assert(self.dleq_verify(dis['g'], Xi, dis['pks'],
         dis['y2'], dis['c'], dis['a1'], dis['a2'], dis['z'])==True)
        
        print("SCH PVSS verification cost ",time.time()- starttime)                 
        return True

    def reconstruct(self,dis):
        # g^s sent by shareholders
        # stidle=[self.group.init(G2,1)]
        Xi=dis['y1']
        Yi=dis['y2']
        Si=[self.group.init(G2,1)]
        for i in range(1, N+1):
            Si.append(Yi[i]**(1/self.sks[i]))
        # TODO add proofs
        
        indexArr = [i for i in range(1,N+1)]

        random.shuffle(indexArr)
        indexArr=indexArr[0:t]
        y = self.util.recoverCoefficients(indexArr)
        z=self.group.init(G2,1)
        for i in indexArr:    
            z *= Si[i]**y[i]    

        if self.S!=z: 
            return -2
        return z

groupObj = PairingGroup(setting.curveName)
scrape = SCHPVSS(groupObj)
print("N=%d,t=%d"%(N,t))
dis= scrape.distribute()
# print(scrape.verify(dis["shat"], dis["vs"]))
print(scrape.verify(dis))
scrape.reconstruct(dis)


