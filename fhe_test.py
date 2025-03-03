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
    plain_len=len(plain_t)
    
    mult_depth = 1
    scale_mod_size = 50
    batch_size = 8
    
    parameters = CCParamsCKKSRNS()
    parameters.SetMultiplicativeDepth(mult_depth)
    parameters.SetScalingModSize(scale_mod_size)
    parameters.SetBatchSize(batch_size)
    cc = GenCryptoContext(parameters)
    cc.Enable(PKESchemeFeature.PKE)
    cc.Enable(PKESchemeFeature.KEYSWITCH)
    cc.Enable(PKESchemeFeature.LEVELEDSHE)
    
    
    keys = cc.KeyGen()
    cc.EvalMultKeyGen(keys.secretKey)
    cc.EvalRotateKeyGen(keys.secretKey, [1, -2])
    precision=1
    
    ptx=cc.MakeCKKSPackedPlaintext(plain_t)
    c1 = cc.Encrypt(keys.publicKey, ptx)
    dec = cc.Decrypt(c1, keys.secretKey)

    dec.SetLength(plain_len)
    dec.GetFormattedValues(precision)
    vals=dec.GetRealPackedValue()
    final=[]
    for i in vals:
        rounded=round(i, 1)
        final.append(rounded)
        
    assert np.all(plain_t == final) #numpy.all checks if array elements are the same

@pytest.mark.parametrize("model", [tfhe], ids=["TFHE"])
def test_enc_dec_tfhe(model):
    rng = np.random.RandomState(123)
    plain_t=[0, 1, 0, 1]
    private, public=get_methods(model, "generate_key")(rng)
    cipher=get_methods(model, "encrypt")(rng, private, np.array(plain_t))
    dec=get_methods(model, "decrypt")(private, cipher)
    assert np.all(plain_t == dec)
        
    
