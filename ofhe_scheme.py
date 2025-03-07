from abc import ABC, abstractmethod
import math, json
import openfhe as ofhe
import numpy as np
from tfhe_scheme import FHEScheme
import collections

from openfhe import(
    CryptoContext,
    CCParamsCKKSRNS,
    GenCryptoContext,
    PKESchemeFeature,
    Plaintext
)

class OpenFHE(FHEScheme):
    def __init__(self):
        self.cc=None # the cc value will be used for key generation, packing plaintext, encryption, and decryption
        self.private=None
        self.public=None
        self.plaintext=None
        self.plain_type=None
        # maybe make a variable for input type, as different operations are performed on strings

    #staticmethod is used here because these methods aren't bound to class objects   
    @staticmethod
    def setup_ckks(size):
        mult_depth = 1 # the maximum number of multiplications an HE scheme is built to perform
        scale_mod_size = 50 # the "key size", how many bits the key will be
        batch_size = size # number of values to be encrypted
        
        parameters = CCParamsCKKSRNS() # create a CCParamsCKKSRNS object
        parameters.SetMultiplicativeDepth(mult_depth) 
        parameters.SetScalingModSize(scale_mod_size)
        parameters.SetBatchSize(batch_size)
        # multiplicative depth, key size, and batch size are set to the above values

        cc = GenCryptoContext(parameters) # creates a CKKS instance using the parameters
        # methods will be invoked using the above
        cc.Enable(PKESchemeFeature.PKE) # PKE = Public Key Encryption
        # Enabling this feature allows us to create public and private keys to use with our plaintext
        cc.Enable(PKESchemeFeature.LEVELEDSHE) # LEVELEDSHE = Leveled Somewhat Homomorphic Encryption
        # Enabling LeveledSHE allows us to perform homomorphic addition
        return cc

    @staticmethod
    def nearest_power_padding(obj: list | str, obj_len):
        # used with OpenFHE, as its batches must have lengths that are powers of two
        exp=int(math.log2(obj_len)) # get log2 of the string's length
        if (2**exp == obj_len):
            return obj # if the length is already a power of two, return the string as is
        else: # if it's not a power of two, find the closest power of 2
            nearest_power=2**(exp + 1) # raise 2 to the power of the result of log2 plus 1
            pad_len=nearest_power - obj_len # subtract the object length from the closest power of two
            if type(obj)==str:
                padded_str=obj + (" " * pad_len) # add the previously found difference to the string as padding
                return padded_str
            else: 
                for i in range(pad_len):
                    obj.append(0)
                return obj
    @staticmethod
    def remove_padding(padded, plain_len):
        no_pad=padded[:plain_len]
        return no_pad

    def getKeys(self):
        keys=self.cc.KeyGen()
        private=keys.secretKey
        public=keys.publicKey
        # publicKey is used for encryption, secretKey is used for decryption
        return private, public

    def encrypt(self, plaintext):
        self.plaintext=plaintext
        self.plain_type=type(plaintext)
        if(self.plain_type==int or self.plain_type==float):
            plaintext=[plaintext]
            start_len=1
        else:
            start_len=len(plaintext) 
        plain_t=OpenFHE.nearest_power_padding(plaintext, start_len) # add padding to ensure length is a power of two

        if self.plain_type==str:
            plain_t=[(byte) for byte in plain_t.encode("utf-8")] # encode string characters into bytes using utf-8 format
        cc = OpenFHE.setup_ckks(len(plain_t))  # create CKKS parameters for encryption
        self.cc=cc # save crypto context for use in other methods

        if (self.private==None or self.public==None): # if there are no keys
            self.private, self.public=self.getKeys() # run the getKeys method
        ptx=self.cc.MakeCKKSPackedPlaintext(plain_t) # converts the list of values to a plaintext object

        cipher=self.cc.Encrypt(self.public, ptx) # encrypt the ciphertext
        return cipher

    def decrypt(self, ciphertext):
        decrypt=self.cc.Decrypt(ciphertext, self.private)
        vals=decrypt.GetRealPackedValue() # extract the plaintext values and put them in a list
        final=[]
        for i in vals:
            rounded=round(i, 1)
            final.append(rounded) # round the extracted values to one decimal place
        if(self.plain_type==str):
            encoded=[]
            for i in final:
                i_val=int(i)
                encoded.append(i_val)
            no_pad=OpenFHE.remove_padding(encoded, len(self.plaintext))
            if(no_pad==[(byte)for byte in self.plaintext.encode("utf-8")]):
                decrypt=self.plaintext
                return decrypt
        elif(self.plain_type==int):
            for i in final:
                i_val=int(i)
            return i_val
        else:
            return final
    
    def add(self, plain1, plain2):
        cipher1=self.encrypt(plain1)
        cipher2=self.encrypt(plain2)
        enc_sum = self.cc.EvalAdd(cipher1, cipher2)
        dec_sum = self.decrypt(enc_sum)
        return dec_sum

    def generateKeyDict(self):
        sample_keys=collections.namedtuple('Keys', ['power', 'context', 'private', 'public'])
        f=open("Crypto_Context.txt", "a") 
        for i in range(1, 10):
            num=2**i
            cc=OpenFHE.setup_ckks(num)
            self.cc=cc
            private, public = self.getKeys()
            new_val=sample_keys(num, cc, private, public)
            key_dict=new_val._asdict()
            f.write(str(new_val))
            f.write("\n")
        f.close()

        # this code is used to invoke this method
        # scheme2=ofhe_scheme.OpenFHE()
        # scheme2.generateKeyDict()







        
