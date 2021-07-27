import hashlib
from time import time
from ecdsa import SigningKey, VerifyingKey, NIST384p


class BlockChain:

    def __init__(self):
    
        #transactions
        self.pendingTransactions = {}
        self.confirmedTransactions = {}
        
              
        self.blockChain = []
                
    def addTransaction(self,transaction):
        hashID = hashlib.sha256(f'{transaction}'.encode()).hexdigest()  #encode() to get byte string
        self.pendingTransactions[hashId] = transaction
        
        
        
    #verify&append
    def verifyTransactions(self,transactions):
        
        #trxnformat
        #transaction = { 'metadata': {'vin_sz':insz, 'vout_sz':outsz},
        #     'in': [{'prev_out':{'hash':phash,'n':index}, 'scriptSig':{'pubKey':pbk,'sign':sign}},],
        #  'out':[{'value':value, 'toPbKeyHash':rcpntPbKeyHash},],
        #            }
        
        for t in transactions:
            prevHash = t['in']['prev_out']['hash'] 
            
            outputIndex = t['in']['prev_out']['n'] 
            
            signature = t['in']['scriptSig']['sign']
            
            refTrnsctn = getTransaction(prevHash)
            
            if (refTrnsctn is False):
                return False
                
            else:
                
                toCheckPkHash = refTrnsctn['out'][outputIndex]['toPbKeyHash']
                
                pbKey = VerifyingKey.from_string(t['in']['scriptSig']['pubKey'], curve=NIST384p)
            
            
                strKey = f'{pbKey}'.encode()
            
                thisHash = hashlib.sha256(strKey).hexdigest()
            
                toCheckTrHash = refTrnsctn['metadata']['hash'] 
            
                if ( toCheckPkHash is thisHash ):
                
                    if ( pbKey.verify(signature, f'{thisHash}'.encode()) is False):
                        return False
             
                self.confirmedTransactions.append(t)
          
        return True
               
    def getTransaction(self,hash):
        
        if hash in self.confirmedTransactions.keys():
            return self.confirmedTransactions[hash]
        
        else:
            return False
        
    
    def proposeBlock(self,blockheader,transactions): #blkhdr:bits,nonce,trlist...
        
        #blockformat
        #block = {
        # 'blockheader':{'nonce': nonce,'time':timest,'bits':bitstrgt,'prvBlockHash': previous_hash,'mrklroothash':hashmrklroot,'version':version,},
        #  'transactions': transactions, #merkletree
        #        }
        
        
        block = {
           'blockheader':self.blockheader,
            'transactions':self.transactions, #merkletree
            
            
        }
        
        self.validateBlock(block)
        
       
    def validateBlock(self,block):    #apndiftrue
        vrfd = self.verifyTransactions(block['transactions'])
        hdr = block['blockheader']
        if(vrfd):
            hashCheck = hashlib.sha256(f'{hdr}'.encode()).hexdigest()
            
            if ( str(hashCheck[:n]) is ( '0'*n ) ): ##chckbittrgt
                print('Block added successfully!')
                self.blockChain.append(block)

    #genKeys
    def createID(self): 
        pvtKey = SigningKey.generate(curve=NIST384p)
        pvtKeyString = pvtKey.to_string()
        print('Private Key:', pvtKeyString)
        
        pblKey = pvtKey.verifying_key
        pblKeyString = pblKey.to_string()
        print('Public Key', pblKeyString)
        
    def signMsg(self,msg,pvtkey): ##msg==hashedtrnsctn
        
        msg = f'{msg}'.encode()
        hashedMsg = hashlib.sha256(msg).hexdigest()
        
        pvtKey = SigningKey.from_string(pvtkey, curve=NIST384p)
        
        signature = pvtKey.sign(b"msg")
        
        return signature
    
    def viewBlockChain(self):
        return self.blockChain

        
    
                  
                  
                  
                  
                  
    
    
    
    
        
    
    
       
    
    
        
        

