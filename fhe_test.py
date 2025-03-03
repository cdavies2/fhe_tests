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
    BinFHEContext as bfc,
    CryptoContext as cc,
    CCParamsCKKSRNS as ckks_of,
    Plaintext
)


ofhe_methods=dict([("generate_key", bfc.KeyGen), 
("encrypt", cc.Encrypt), ("decrypt", cc.Decrypt),
])

# add evalAdd method later

tfhe_methods=dict([("generate_key", tfhe_key_pair),
("encrypt", tfhe_encrypt), ("decrypt", tfhe_decrypt)])

def get_methods(model, method):
    if(model==ofhe):
        return ofhe_methods[method]
    if(model==tfhe):
        return tfhe_methods[method]


@pytest.mark.parametrize("model", [tfhe, ofhe], ids=["TFHE", "OpenFHE"])
def test_enc_dec(model):
    rng = np.random.RandomState(123)
    plain_t=[0, 1, 0, 1]
    plain_len=len(plain_t)
    # poly=Polynomial(plain_t)
    # plain_o=Plaintext.Decode(poly)
    if model==tfhe:
        private, public=get_methods(model, "generate_key")(rng)
        cipher=get_methods(model, "encrypt")(rng, private, np.array(plain_t))
        dec=get_methods(model, "decrypt")(private, cipher)
    else:
        plain_o=cc.MakePackedPlaintext(plain_t, 1, 0)
        private, public=get_methods(model, "generate_key")
        cipher=get_methods(model, "encrypt")(np.array(plain_o), private)
        dec=get_methods(model, "decrypt")(cipher, private)
    assert np.all(plain_t == dec) #numpy.all checks if array elements are the same
