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
    BinFHEContext,
    CryptoContext,
    CCParamsCKKSRNS,
    GenCryptoContext,
    PKESchemeFeature,
    Plaintext
)

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

class FHEScheme(ABC):
    @abstractmethod
    def getKeys(self, seed=None):
        ...

    @abstractmethod
    def encrypt(self, plaintext):
        ...

    @abstractmethod
    def decrypt(self, ciphertext):
        ...


class OpenFHEScheme(FHEScheme):
    ...

class TFHEScheme(FHEScheme):
    ...

ofhe_methods = {  
    "generate_key": BinFHEContext.KeyGen,
    "encrypt": CryptoContext.Encrypt,
    "decrypt": CryptoContext.Decrypt
}

# add evalAdd method later

tfhe_methods = {
    "generate_key": tfhe_key_pair,
    "encrypt": tfhe_encrypt,
    "decrypt": tfhe_decrypt
}

def get_methods(model, method):
    if(model==ofhe):
        return ofhe_methods[method]
    if(model==tfhe):
        return tfhe_methods[method]


@pytest.mark.parametrize("model", [ofhe], ids=["OpenFHE"])
def test_enc_dec_ofhe(model):
    plain_t=[2.0, 1.0, 2.0, 1.0]
    cc = setup_ofhe_ckks(4)
    keys = cc.KeyGen() # generates two keys to be stored in the "keys" variable
    # publicKey is used for encryption, secretKey is used for decryption
    precision=1 # tells us the decimal precision of our resulting values
    
    ptx=cc.MakeCKKSPackedPlaintext(plain_t) # converts the list of values to a plaintext object
    c1 = cc.Encrypt(keys.publicKey, ptx) # encrypt the plaintext object using the public key
    # c1=get_methods(model, "encrypt")(keys.publicKey, ptx) # this version of the command uses our dictionary
    dec = cc.Decrypt(c1, keys.secretKey) # decrypt using the secret key
    # dec = get_methods(model, "decrypt")(c1, keys.secretKey)

    dec.GetFormattedValues(precision) # format the decrypted values to proper decimal point
    vals=dec.GetRealPackedValue() # extract the plaintext values and put them in a list
    final=[]
    for i in vals:
        rounded=round(i, 1)
        final.append(rounded) # round the extracted values to one decimal place
        
    assert np.all(plain_t == final) #numpy.all checks if array elements are the same


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
    plain_t=plaintext 
    bit_list=[] # this object will be used if we have a list of integers
    for i in plain_t:
            bit=int_to_bitarray(i) # convert the integer to bits
            bit_list.append(bit) # add the integer to the bit_list
        
    private, public = get_methods(model, "generate_key")(rng)
    dec = [] # variable used if decrypting a list of integers
    for i in bit_list:
        cipher=get_methods(model, "encrypt")(rng, private, np.array(i)) # encrypt plaintext
        dec_item=get_methods(model, "decrypt")(private, cipher) # decrypt plaintext
        dec_item=bitarray_to_int(dec_item) # convert bits back to integers
        dec.append(dec_item) # add the values to a list
    assert np.all(plain_t == dec) # check that values match


@pytest.mark.parametrize("model, plaintext", 
[(tfhe, 25)], ids=["TFHE int"])
def test_int_enc_dec_tfhe(model, plaintext):
    rng = np.random.RandomState(123)
    plain_t=int_to_bitarray(plaintext)
    private, public = get_methods(model, "generate_key")(rng)
    cipher=get_methods(model, "encrypt")(rng, private, np.array(plain_t))
    dec=get_methods(model, "decrypt")(private, cipher)
    assert np.all(plain_t == dec) # check that values match

#def test_add_ofhe(model, plaintext):

