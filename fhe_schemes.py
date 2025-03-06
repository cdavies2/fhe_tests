from abc import ABC, abstractmethod
import os, pytest, math
import openfhe as ofhe
import tfhe as tfhe
import numpy as np

from openfhe import(
    CryptoContext,
    CCParamsCKKSRNS,
    GenCryptoContext,
    PKESchemeFeature,
    Plaintext
)

from tfhe.keys import(
    tfhe_decrypt,
    tfhe_encrypt,
    tfhe_key_pair
)


class FHEScheme(ABC):
    @abstractmethod
    def getKeys(self):
        pass

    @abstractmethod
    def encrypt(self, plaintext):
        pass

    @abstractmethod
    def decrypt(self, key, ciphertext):
        pass

# these abstract classes are used to provide consistency when using OpenFHE and TFHE
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
        return cc

    @staticmethod
    def nearest_power_padding(obj: str | list, obj_len):
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
                    obj.append(" ")
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
        else:
            return final
        

class TFHE(FHEScheme):
    def __init__(self):
        self.seed=np.random.RandomState(123)
        self.private=None
        self.public=None
        self.plaintext=None
        self.plain_type=None
        
    @staticmethod
    def ints_to_bits(plain_t):
        bit_list=[] # this object will be used if we have a list of integers
        if type(plain_t)==list:
            for i in plain_t:
                bit=np.array([((i >> j) & 1 != 0) for j in range(8)]) # convert the integer to bits
                # >> is the piecewise shift operator
                # we choose 8 for our number of bits because we are encoding bytes for our strings/ints
                bit_list.append(bit) # add the encoded integer to the bit_list
            return bit_list
        else:
            bit = (np.array([((plain_t >> j) & 1 != 0) for j in range(8)])) 
            # if one integer is sent, convert it to a bit array
            return bit #return the array

    @staticmethod
    def bits_to_ints(bit_list):
        int_answer = 0  #this converts bits back to their initial number values
        for i in range(8):
            int_answer = int_answer | (bit_list[i] << i)
        return int_answer  

    def getKeys(self):
        private, public = tfhe_key_pair(self.seed)
        return private, public


    def encrypt(self, plaintext):
        self.plaintext=plaintext
        self.plain_type=type(plaintext)
        if (self.plain_type==str):
            plaintext=[(byte) for byte in plaintext.encode("utf-8")]
        bits=TFHE.ints_to_bits(plaintext)
        if (self.private==None or self.public==None): # if there are no keys
            self.private, self.public=self.getKeys()
        cipher_list=[]
        if type(plaintext)==list:
            for i in bits:
                cipher=tfhe_encrypt(self.seed, self.private, np.array(i)) # encrypt plaintext
                cipher_list.append(cipher)
            return cipher_list
        else:
            cipher=tfhe_encrypt(self.seed, self.private, np.array(bits))
            return cipher


    def decrypt(self, ciphertext):
        decrypt=[]
        if type(ciphertext)==list:
            for i in ciphertext:
                dec_item=tfhe_decrypt(self.private, i)
                dec_item=TFHE.bits_to_ints(dec_item)
                decrypt.append(dec_item)
        else:
            dec_bits=tfhe_decrypt(self.private, ciphertext)
            decrypt=TFHE.bits_to_ints(dec_bits)
        if (self.plain_type==str):
            if (decrypt==[(byte) for byte in self.plaintext.encode("utf-8")]):
                decrypt=self.plaintext
        return decrypt