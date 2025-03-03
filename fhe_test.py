import os, pytest
import openfhe as ofhe
import numpy as np
from numpy.polynomial import Polynomial
import tfhe as tfhe
from tfhe.keys import(
    tfhe_decrypt,
    tfhe_encrypt,
    tfhe_key_pair
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



ofhe_methods=dict([("generate_key", BinFHEContext.KeyGen), 
("encrypt", CryptoContext.Encrypt), ("decrypt", CryptoContext.Decrypt),
])

# add evalAdd method later

tfhe_methods=dict([("generate_key", tfhe_key_pair),
("encrypt", tfhe_encrypt), ("decrypt", tfhe_decrypt)])

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

@pytest.mark.parametrize("model", [tfhe], ids=["TFHE"])
def test_enc_dec_tfhe(model):
    rng = np.random.RandomState(123)
    plain_t=[0, 1, 0, 1]
    private, public=get_methods(model, "generate_key")(rng)
    cipher=get_methods(model, "encrypt")(rng, private, np.array(plain_t))
    dec=get_methods(model, "decrypt")(private, cipher)
    assert np.all(plain_t == dec)
        
    
