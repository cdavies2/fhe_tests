from abc import ABC, abstractmethod
import os, pytest
import openfhe as ofhe
import tfhe as tfhe
import numpy as np
# from numpy.polynomial import Polynomial
from tfhe.keys import(
    tfhe_decrypt,
    tfhe_encrypt,
    tfhe_key_pair
)
from tfhe.utils import(
    bitarray_to_int,
    int_to_bitarray
)

from openfhe import(
    CryptoContext,
    CCParamsCKKSRNS,
    GenCryptoContext,
    PKESchemeFeature,
    Plaintext
)

# the strings below will be used to test encryption and decryption of encoded strings
str1 = "Hi there" # this has eight characters, which is a power of two
str2 = "the magic words are squeamish ossifrage" + (" " * 25) # temp solution, adding padding manually to reach a power of 2

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

def ints_to_bits_tfhe(plain_list):
    bit_list=[] # this object will be used if we have a list of integers
    for i in plain_list:
        bit=int_to_bitarray(i) # convert the integer to bits
        bit_list.append(bit) # add the integer to the bit_list
    return bit_list
    
        

class FHEScheme(ABC):
    @abstractmethod
    def getKeys(self):
        pass

    @abstractmethod
    def encrypt(self, plaintext, key):
        pass

    @abstractmethod
    def decrypt(self, ciphertext, key):
        pass


class OpenFHEScheme(FHEScheme):
    def __init__(self, seed):
        self.seed=seed
    def getKeys(self):
        keys=self.seed.KeyGen()
        return keys
    def encrypt(self, key, plaintext):
        cipher=self.seed.Encrypt(key, plaintext)
        return cipher
    def decrypt(self, key, ciphertext):
        decrypt=self.seed.Decrypt(ciphertext, key)
        return decrypt


class TFHEScheme(FHEScheme):
    def __init__(self, seed):
        self.seed=seed
    def getKeys(self):
        private, public=tfhe_key_pair(self.seed)
        return private, public
    def encrypt(self, key, plaintext):
        cipher=tfhe_encrypt(self.seed, key, plaintext)
        return cipher
    def decrypt(self, key, ciphertext):
        decrypt=tfhe_decrypt(key, ciphertext)
        return decrypt


@pytest.mark.parametrize("model, plaintext", 
[
    (ofhe, [2.5, 3.4, 1.8, 5.2]),
    (ofhe, [2, 1, 2, 1]),
], 
ids=["OpenFHE floats", "OpenFHE ints"])
def test_enc_dec_nums_ofhe(model, plaintext):
    plain_t=plaintext
    cc = setup_ofhe_ckks(len(plain_t))
    ofhe_scheme=OpenFHEScheme(cc)
    keys = ofhe_scheme.getKeys() # generates two keys to be stored in the "keys" variable
    # publicKey is used for encryption, secretKey is used for decryption
    precision=1 # tells us the decimal precision of our resulting values
    ptx=cc.MakeCKKSPackedPlaintext(plain_t) # converts the list of values to a plaintext object
    c1 = cc.Encrypt(keys.publicKey, ptx) # encrypt the plaintext object using the public key
    dec = cc.Decrypt(c1, keys.secretKey) # decrypt using the secret key
    

    dec.GetFormattedValues(precision) # format the decrypted values to proper decimal point
    vals=dec.GetRealPackedValue() # extract the plaintext values and put them in a list
    final=[]
    for i in vals:
        rounded=round(i, 1)
        final.append(rounded) # round the extracted values to one decimal place
        
    assert np.all(plain_t == final) #numpy.all checks if array elements are the same

@pytest.mark.parametrize("model, plaintext",
[(ofhe, str1), (ofhe, str2)], ids=["OpenFHE short string", "OpenFHE magic words"])
def test_enc_dec_str_ofhe(model, plaintext):
    plain_t=plaintext
    encoded_plain=[(char) for char in plaintext.encode("utf-8")]
    cc = setup_ofhe_ckks(len(encoded_plain))
    keys = cc.KeyGen()
    precision=1
    ptx=cc.MakeCKKSPackedPlaintext(encoded_plain) 
    c1 = cc.Encrypt(keys.publicKey, ptx) 
    dec = cc.Decrypt(c1, keys.secretKey) 
    dec.GetFormattedValues(precision)
    vals=dec.GetRealPackedValue() # extract the plaintext values and put them in a list
    final=[]
    for i in vals:
        rounded=round(i, 1)
        final.append(rounded) # round the extracted values to one decimal place
    
    assert np.all(encoded_plain == final)







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
    bit_list=ints_to_bits_tfhe(plaintext)
    private, public = tfhe_scheme.getKeys()
    # private, public = get_methods(model, "generate_key")(rng)
    dec = [] # variable used if decrypting a list of integers
    for i in bit_list:
        cipher=tfhe_scheme.encrypt(private, np.array(i)) # encrypt plaintext
        dec_item=tfhe_scheme.decrypt(private, cipher) # decrypt plaintext
        dec_item=bitarray_to_int(dec_item) # convert bits back to integers
        dec.append(dec_item) # add the values to a list
    assert np.all(plain_t == dec) # check that values match


@pytest.mark.parametrize("model, plaintext", 
[(tfhe, 25)], ids=["TFHE int"])
def test_int_enc_dec_tfhe(model, plaintext):
    rng = np.random.RandomState(123)
    tfhe_scheme=TFHEScheme(rng)
    plain_t=int_to_bitarray(plaintext)
    private, public = tfhe_scheme.getKeys()
    cipher=tfhe_scheme.encrypt(private, np.array(plain_t))
    dec=tfhe_scheme.decrypt(private, cipher)
    assert np.all(plain_t == dec) # check that values match


@pytest.mark.parametrize("model, plaintext",
[(tfhe, str1), (tfhe, str2)], ids=["TFHE short string", "TFHE magic words"])
def test_str_enc_dec_tfhe(model, plaintext):
    rng = np.random.RandomState(123)
    tfhe_scheme=TFHEScheme(rng)
    private, public = tfhe_scheme.getKeys()
    plain_t=plaintext
    encoded_plain=[(char) for char in plaintext.encode("utf-8")]
    bit_list=ints_to_bits_tfhe(encoded_plain)
    # private, public = get_methods(model, "generate_key")(rng)
    dec = [] 
    for i in bit_list:
        cipher=tfhe_scheme.encrypt(private, np.array(i))
        dec_item=tfhe_scheme.decrypt(private, cipher) 
        dec_item=bitarray_to_int(dec_item) 
        dec.append(dec_item) 
    assert encoded_plain == dec



#def test_add_ofhe(model, plaintext):

