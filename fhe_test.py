from abc import ABC, abstractmethod
import os, pytest, math
# import openfhe as ofhe
import ofhe_scheme
import tfhe as tfhe
import numpy as np
import tfhe_scheme


# the strings below will be used to test encryption and decryption of encoded strings
str1 = "Hello" 
str2 = "the magic words are squeamish ossifrage"

           
# @pytest.mark.parametrize("model, plaintext", 
# [
#     (ofhe, [2.5, 3.4, 1.8, 5.2]),
#     (ofhe, [2, 1, 2, 1]),
# ], 
# ids=["OpenFHE floats", "OpenFHE ints"])
# def test_enc_dec_nums_ofhe(model, plaintext):
#     scheme=ofhe_scheme.OpenFHE() # create OpenFHEScheme object

#     c1 = scheme.encrypt(plaintext) # encrypt the plaintext object using the public key
#     dec = scheme.decrypt(c1) # decrypt using the secret key
#     assert np.all(plaintext == dec) #np.all checks if array elements are the same



# @pytest.mark.parametrize("model, plaintext",
# [(ofhe, str1), (ofhe, str2)], ids=["OpenFHE short string", "OpenFHE magic words"])
# def test_enc_dec_str_ofhe(model, plaintext):
#     scheme=ofhe_scheme.OpenFHE() # create scheme, encrypt and decrypt as you would with number input
    
#     c1 = scheme.encrypt(plaintext) 
#     dec = scheme.decrypt(c1)
    
#     assert np.all(plaintext == dec)



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
    scheme=tfhe_scheme.TFHE() # initialize TFHE object, creating random seed
    c1=scheme.encrypt(plaintext) # encrypt plaintext
    dec=scheme.decrypt(c1) # decrypt plaintext
    
    assert np.all(plaintext == dec) # check that values match


@pytest.mark.parametrize("model, plaintext", 
[(tfhe, 25)], ids=["TFHE int"])
def test_int_enc_dec_tfhe(model, plaintext):
    scheme=tfhe_scheme.TFHE()
    cipher=scheme.encrypt(plaintext)
    dec=scheme.decrypt(cipher)
    assert np.all(plaintext == dec) # check that values match


@pytest.mark.parametrize("model, plaintext",
[(tfhe, str1), (tfhe, str2)], ids=["TFHE short string", "TFHE magic words"])
def test_str_enc_dec_tfhe(model, plaintext):
    scheme=tfhe_scheme.TFHE()
    cipher=scheme.encrypt(plaintext)
    dec=scheme.decrypt(cipher) 
    assert plaintext == dec



# @pytest.mark.parametrize("model", [ofhe, tfhe], ids=["OpenFHE", "TFHE"])
# def test_both_schemes_str(model):
#     plaintext= "encrypt and decrypt"
#     if model == ofhe:
#         scheme=ofhe_scheme.OpenFHE()
#     else:
#         scheme=tfhe_scheme.TFHE()
#     cipher=scheme.encrypt(plaintext)
#     dec=scheme.decrypt(cipher) 
#     assert plaintext == dec

# @pytest.mark.parametrize("model, plaintext", [(ofhe, [1, 0, 0, 1]), 
# (tfhe, [1, 0, 0, 1]), (ofhe, [2, 5, 6, 7, 3, 8]), (tfhe, [2, 5, 6, 7, 3, 8])], 
# ids=["OpenFHE bits", "TFHE bits", "OpenFHE ints", "TFHE ints"])
@pytest.mark.parametrize("model, plaintext", [(tfhe, [2, 5, 6, 7, 3, 8]),
(tfhe, [1, 0, 0, 1])], ids=["TFHE bits", "TFHE ints"])
def test_both_schemes_num(model, plaintext):
    # if model == ofhe:
    #     scheme=ofhe_scheme.OpenFHE()
    # else:
    scheme=tfhe_scheme.TFHE()
    cipher=scheme.encrypt(plaintext)
    dec=scheme.decrypt(cipher) 
    assert plaintext == dec
    
# @pytest.mark.parametrize("model, plaintext1, plaintext2", [(ofhe, [1, 2, 3, 4], [2, 5, 7, 8]), 
# (ofhe, 25, 10), (tfhe, [0, 1], [1, 0])], ids=["OpenFHE add int lists", "OpenFHE add ints", "TFHE add bits"])
@pytest.mark.parametrize("model, plaintext1, plaintext2", [(tfhe, [0, 1], [1, 0])],
ids=["TFHE add bits"])
def test_addition(model, plaintext1, plaintext2):
    # if model == ofhe:
    #     scheme=ofhe_scheme.OpenFHE()
    # else:
    scheme=tfhe_scheme.TFHE()
    l_sums=[]
    if (type(plaintext1)==list):
        for i in range(len(plaintext1)):
            t_sum=(plaintext1[i] + plaintext2[i])
            l_sums.append(t_sum)
    else:
        l_sums=plaintext1 + plaintext2
    cipher_sum=scheme.add(plaintext1, plaintext2)
    assert np.all(l_sums==cipher_sum)

