# BlockChain python implementation 

This is a loose implementation/simulation in Python of my understanding of the technicalities of Bitcoin which is based on BlockChain Technology . 

These technicalities include how a block is verified and added to the chain, by verifying its legibility(transactions placed in it).

In Bitcoin, this verification mechanism (of transactions) is implemented through a native stack-based language.

### Python modules used:

SHA256 used for hashing
ECDSA used as the Digital Signature Algorithm

```bash

pip install hashlib  #SHA-256

pip install ecdsa    #Signatures

```

### Transaction and Block data format

```python

block = {
         'blockheader':{'nonce': nonce,'time':timest,'bits':bitstrgt,'prvBlockHash': previous_hash,'mrklroothash':hashmrklroot,'version':version,},
          'transactions': transactions, #merkletree
                }


transaction = { 'metadata': {'vin_sz':insz, 'vout_sz':outsz},
             'in': [{'prev_out':{'hash':hash,'n':index}, 'scriptSig':{'pubKey':pbk,'sign':sign}},],
             'out':[{'value':value, 'toPbKeyHash':rcpntPbKeyHash},],
                       }


```


