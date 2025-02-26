import os, pytest
import openfhe as ofhe
import numpy
import tfhe as tfhe
from tfhe.keys import(
    tfhe_decrypt,
    tfhe_encrypt,
    tfhe_key_pair
)
from openfhe import(
    CryptoContext,
    CCParamsCKKSRNS
)

# ofhe_methods=dict(["generate_key", KeyGen], 
# ["encrypt", Encrypt], ["decrypt", Decrypt], 
# ["add", EvalAdd])

tfhe_methods=dict([("generate_key", tfhe_key_pair),
("encrypt", tfhe_encrypt), ("decrypt", tfhe_decrypt)])

def get_methods(model, method):
    # if(model==ofhe):
    #     return ofhe_methods[method]
    if(model==tfhe):
        return tfhe_methods[method]


@pytest.mark.parametrize("model", [tfhe], ids=["TFHE"])
def test_enc_dec(model):
    rng = numpy.random.RandomState(123)
    plain=[0, 1]
    private, public=get_methods(model, "generate_key")(rng)
    #edit this to account for ofhe encryption having more parameters
    cipher=get_methods(model, "encrypt")(rng, private, numpy.array(plain))
    dec=get_methods(model, "decrypt")(private, cipher)
    assert numpy.all(plain == dec) #numpy.all checks if array elements are the same
