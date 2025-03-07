from abc import ABC, abstractmethod
import os, pytest, math
import tfhe as tfhe
import numpy as np

from tfhe.boot_gates import AND, XOR
from tfhe.keys import(
    empty_ciphertext,
    tfhe_decrypt,
    tfhe_encrypt,
    tfhe_key_pair,
    tfhe_parameters
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
    
    @abstractmethod
    def add(self, cipher1, cipher2):
        pass


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
    
    def add(self, plain1, plain2):
        # modifying the originally given half-adder code
        cipher1=self.encrypt(plain1)
        cipher2=self.encrypt(plain2)

        # original code is commented out
        # ciphertext1 = tfhe_encrypt(rng, private, np.array(cipher1))
        # ciphertext2 = tfhe_encrypt(rng, private, np.array(cipher2))
        final_list=[]
        for i in range(len(cipher1)):

            params = tfhe_parameters(self.public)
            shape = cipher1[i].shape
            result_carry = empty_ciphertext(params, shape)
            result_sum = empty_ciphertext(params, shape)

            AND(self.public, result_carry, cipher1[i], cipher2[i])
            XOR(self.public, result_sum, cipher1[i], cipher2[i])
            # AND(public, result_carry, ciphertext1, ciphertext2)
            # XOR(public, result_sum, ciphertext1, ciphertext2)

            answer_bits_carry = self.decrypt(result_carry)
            answer_bits_sum = self.decrypt(result_sum)
            carry_list=answer_bits_carry.tolist()
            sum_list=answer_bits_sum.tolist()
            final_list.append(sum_list)

        # answer_bits_carry = tfhe_decrypt(private, result_carry)
        # answer_bits_sum = tfhe_decrypt(private, result_sum)
        # carry_list=answer_bits_carry.tolist()
        # answer=[]
        # for i in carry_list:
        #     if i == False:
        #         answer.append(1)
        #     else:
        #         answer.append(0)
        #answer=TFHE.bits_to_ints(final_list)
        return final_list 
    



