from abc import ABC, abstractmethod
import os, pytest, math
import openfhe as ofhe
import tfhe as tfhe
import numpy as np
from numpy.typing import NDArray

from tfhe.keys import(
    tfhe_decrypt,
    tfhe_encrypt,
    tfhe_key_pair
)

from openfhe import(
    CryptoContext,
    CCParamsCKKSRNS,
    GenCryptoContext,
    PKESchemeFeature,
    Plaintext
)

# the strings below will be used to test encryption and decryption of encoded strings
str1 = "Hello" 
str2 = "the magic words are squeamish ossifrage"

# the method below creates the necessary context for CKKS encryption to be performed using OpenFHE
def setup_ofhe_ckks(size):
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
        bit = (np.array([((plain_t >> j) & 1 != 0) for j in range(8)])) # if one integer is sent, convert it to a bit array
        return bit #return the array
        

def bits_to_ints(bit_list):
    int_answer = 0  #this converts bits back to their initial number values
    for i in range(8):
        int_answer = int_answer | (bit_list[i] << i)
    return int_answer  


def nearest_power_padding(obj: str | list, obj_len):
    # used with OpenFHE, as its batches must have lengths that are powers of two
    exp=int(math.log2(obj_len)) # get log2 of the string's length
    if (2**exp == obj_len):
        return obj # if the length is already a power of two, return the string as is
    else: # if it's not a power of two, find the closest power of 2
        nearest_power=2**(exp + 1) # raise 2 to the power of the result of log2 plus 1
        pad_len=nearest_power - obj_len # subtract the object length from the closest power of two
        if type(obj)==str:
            padded_str=str_obj + (" " * pad_len) # add the previously found difference to the string as padding
            return padded_str
        else: 
            for i in range(pad_len):
                obj.append(" ")
            return obj

def remove_padding(obj, og_length):
    no_pad=obj[:og_length]
    return no_pad
        
        

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
class OpenFHEScheme(FHEScheme):
    def __init__(self):
        self.cc=None # the cc value will be used for key generation, packing plaintext, encryption, and decryption
        self.private=None
        self.public=None

    def setup_ofhe_ckks(size):
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

    def getKeys(self):
        keys=self.cc.KeyGen()
        private=keys.secretKey
        public=keys.publicKey
        # publicKey is used for encryption, secretKey is used for decryption
        return private, public
    def encrypt(self, plaintext):
        start_len=len(plaintext) 
        plain_t=nearest_power_padding(plaintext, start_len) # add padding as needed
        cc = setup_ofhe_ckks(len(plain_t))  # create CKKS parameters for encryption
        self.cc=cc # save crypto context for use in other methods
        if (self.private==None or self.public==None): # if there are no keys
            self.private, self.public=self.getKeys() # run the getKeys method
        ptx=self.cc.MakeCKKSPackedPlaintext(plaintext) # converts the list of values to a plaintext object
        cipher=self.cc.Encrypt(self.public, ptx) # encrypt the ciphertext
        return cipher
    def decrypt(self, ciphertext):
        decrypt=self.cc.Decrypt(ciphertext, self.private)
        precision=1 # tells us the decimal precision of our resulting values
        decrypt.GetFormattedValues(precision) # format the decrypted values to proper decimal point
        vals=decrypt.GetRealPackedValue() # extract the plaintext values and put them in a list
        # vals=remove_padding(vals, start_len)
        final=[]
        for i in vals:
            rounded=round(i, 1)
            final.append(rounded) # round the extracted values to one decimal place
        return final


class TFHEScheme(FHEScheme):
    def __init__(self, seed):
        self.seed=seed
    def getKeys(self):
        private, public = tfhe_key_pair(self.seed)
        return private, public
    def encrypt(self, key, plaintext):
        # maybe add something here to convert the plaintext to bits if needed
        cipher=tfhe_encrypt(self.seed, key, plaintext)
        return cipher
    def decrypt(self, key, ciphertext):
        decrypt=tfhe_decrypt(key, ciphertext)
        return decrypt

# @pytest.mark.skip(reason="Debug")
@pytest.mark.parametrize("model, plaintext", 
[
    (ofhe, [2.5, 3.4, 1.8, 5.2]),
    (ofhe, [2, 1, 2, 1]),
], 
ids=["OpenFHE floats", "OpenFHE ints"])
def test_enc_dec_nums_ofhe(model, plaintext):
    ofhe_scheme=OpenFHEScheme() # create OpenFHEScheme object

    c1 = ofhe_scheme.encrypt(plaintext) # encrypt the plaintext object using the public key
    dec = ofhe_scheme.decrypt(c1) # decrypt using the secret key
    assert np.all(plaintext == dec) #np.all checks if array elements are the same

@pytest.mark.skip(reason="Debug")
@pytest.mark.parametrize("model, plaintext",
[(ofhe, str1), (ofhe, str2)], ids=["OpenFHE short string", "OpenFHE magic words"])
def test_enc_dec_str_ofhe(model, plaintext):
    plain_t=nearest_power_padding(plaintext, len(plaintext)) # use padding to ensure the string length is a power of two
    encoded_plain=[(byte) for byte in plain_t.encode("utf-8")] # encode string characters into bytes using utf-8 format
    cc = setup_ofhe_ckks(len(encoded_plain)) # create CKKS parameters
    ofhe_scheme=OpenFHEScheme(cc) # create scheme, encrypt and decrypt as you would with number input
    private, public = ofhe_scheme.getKeys() 
    precision=1
    c1 = ofhe_scheme.encrypt(public, encoded_plain) 
    dec = ofhe_scheme.decrypt(private, c1)
    
    assert np.all(encoded_plain == dec)



# observe how tfhe encryption is performed using bits (1s and 0s), integers, and lists of integers
@pytest.mark.parametrize("model, plaintext", 
[
    (tfhe, [0, 1, 0, 1]), 
    (tfhe, [2, 4, 6, 8])
],
ids=[
    "TFHE list bits", 
    "TFHE list ints"
])
def test_list_enc_dec_tfhe(model, plaintext):
    rng = np.random.RandomState(123) # create a random value for key generation
    tfhe_scheme=TFHEScheme(rng)
    plain_t=plaintext
    bit_list=ints_to_bits(plaintext)
    private, public = tfhe_scheme.getKeys()
    dec = [] # variable used if decrypting a list of integers
    for i in bit_list:
        cipher=tfhe_scheme.encrypt(private, np.array(i)) # encrypt plaintext
        dec_item=tfhe_scheme.decrypt(private, cipher) # decrypt plaintext
        dec_item=bits_to_ints(dec_item) # convert bits back to integers
        dec.append(dec_item) # add the values to a list
    assert np.all(plain_t == dec) # check that values match


@pytest.mark.parametrize("model, plaintext", 
[(tfhe, 25)], ids=["TFHE int"])
def test_int_enc_dec_tfhe(model, plaintext):
    rng = np.random.RandomState(123)
    tfhe_scheme=TFHEScheme(rng)
    plain_t=ints_to_bits(plaintext)
    private, public = tfhe_scheme.getKeys()
    cipher=tfhe_scheme.encrypt(private, np.array(plain_t))
    dec=tfhe_scheme.decrypt(private, cipher)
    # dec=bits_to_ints(dec_item)
    assert np.all(plain_t == dec) # check that values match


@pytest.mark.parametrize("model, plaintext",
[(tfhe, str1), (tfhe, str2)], ids=["TFHE short string", "TFHE magic words"])
def test_str_enc_dec_tfhe(model, plaintext):
    rng = np.random.RandomState(123)
    tfhe_scheme=TFHEScheme(rng)
    private, public = tfhe_scheme.getKeys()
    encoded_plain=[(byte) for byte in plaintext.encode("utf-8")]
    bit_list=ints_to_bits(encoded_plain)
    dec = [] 
    for i in bit_list:
        cipher=tfhe_scheme.encrypt(private, np.array(i))
        dec_item=tfhe_scheme.decrypt(private, cipher) 
        dec_item=bits_to_ints(dec_item) 
        dec.append(dec_item) 
    assert encoded_plain == dec

# @pytest.mark.parametrize("model, plaintext", [(ofhe, str2)], ids=["OFHE tfhe bits"])
# def test_ofhe_tfhe_bits(model, plaintext):
#     plaintext=nearest_power_padding(plaintext, len(plaintext))
#     cc=setup_ofhe_ckks(len(plaintext))
#     ofhe_scheme=OpenFHEScheme(cc)
#     encoded_plain=[(byte) for byte in plaintext.encode("utf-8")]
#     private, public = ofhe_scheme.getKeys()
#     bit_list=ints_to_bits(encoded_plain)
#     cipher=ofhe_scheme.encrypt(private, bit_list)
#     dec_item=ofhe_scheme.decrypt(private, cipher) 
#     dec=bits_to_ints(dec_item) 
#     assert encoded_plain == dec


# @pytest.mark.parametrize("model", [tfhe, ofhe], ids=["OpenFHE", "TFHE"])
# def test_both_schemes_str(model):
#     plaintext= "encrypt and decrypt"
#     scheme
#     if model == ofhe:
#         plaintext=nearest_power_padding(plaintext, len(plaintext))
#         cc = setup_ofhe_ckks(len(plaintext))
#         scheme=OpenFHEScheme(cc)
#     else:
#         rng = np.random.RandomState(123)
#         scheme=TFHEScheme(rng)
#     encoded_plain=[(byte) for byte in plaintext.encode("utf-8")]
#     private, public = scheme.getKeys()
#     bit_list=ints_to_bits(encoded_plain)
#     dec=[]
#     for i in bit_list:
#         cipher=scheme.encrypt(private, np.array(i))
#         dec_item=scheme.decrypt(p)
    


#def test_add_ofhe(model, plaintext):

