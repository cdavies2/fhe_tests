from abc import ABC, abstractmethod
import os, pytest, math
import openfhe as ofhe
import tfhe as tfhe
import numpy as np
import fhe_schemes
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

           
@pytest.mark.parametrize("model, plaintext", 
[
    (ofhe, [2.5, 3.4, 1.8, 5.2]),
    (ofhe, [2, 1, 2, 1]),
], 
ids=["OpenFHE floats", "OpenFHE ints"])
def test_enc_dec_nums_ofhe(model, plaintext):
    ofhe_scheme=fhe_schemes.OpenFHE() # create OpenFHEScheme object

    c1 = ofhe_scheme.encrypt(plaintext) # encrypt the plaintext object using the public key
    dec = ofhe_scheme.decrypt(c1) # decrypt using the secret key
    assert np.all(plaintext == dec) #np.all checks if array elements are the same


@pytest.mark.parametrize("model, plaintext",
[(ofhe, str1), (ofhe, str2)], ids=["OpenFHE short string", "OpenFHE magic words"])
def test_enc_dec_str_ofhe(model, plaintext):
    ofhe_scheme=fhe_schemes.OpenFHE() # create scheme, encrypt and decrypt as you would with number input
    
    c1 = ofhe_scheme.encrypt(plaintext) 
    dec = ofhe_scheme.decrypt(c1)
    
    assert np.all(plaintext == dec)



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
    tfhe_scheme=fhe_schemes.TFHE() # initialize TFHE object, creating random seed
    c1=tfhe_scheme.encrypt(plaintext) # encrypt plaintext
    dec=tfhe_scheme.decrypt(c1) # decrypt plaintext
    
    assert np.all(plaintext == dec) # check that values match


@pytest.mark.parametrize("model, plaintext", 
[(tfhe, 25)], ids=["TFHE int"])
def test_int_enc_dec_tfhe(model, plaintext):
    tfhe_scheme=fhe_schemes.TFHE()
    cipher=tfhe_scheme.encrypt(plaintext)
    dec=tfhe_scheme.decrypt(cipher)
    assert np.all(plaintext == dec) # check that values match


# @pytest.mark.skip(reason="Debug")
@pytest.mark.parametrize("model, plaintext",
[(tfhe, str1), (tfhe, str2)], ids=["TFHE short string", "TFHE magic words"])
def test_str_enc_dec_tfhe(model, plaintext):
    tfhe_scheme=fhe_schemes.TFHE()
    cipher=tfhe_scheme.encrypt(plaintext)
    dec=tfhe_scheme.decrypt(cipher) 
    assert plaintext == dec



@pytest.mark.parametrize("model", [ofhe, tfhe], ids=["OpenFHE", "TFHE"])
def test_both_schemes_str(model):
    plaintext= "encrypt and decrypt"
    if model == ofhe:
        scheme=fhe_schemes.OpenFHE()
    else:
        scheme=fhe_schemes.TFHE()
    cipher=scheme.encrypt(plaintext)
    dec=scheme.decrypt(cipher) 
    assert plaintext == dec
    

