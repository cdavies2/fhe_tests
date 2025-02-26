# CKKS, Vanilla Encoding and Decoding
* CKKS is the homomorphic encryption scheme often used with openfhe-python
* In a message m, a vector of values on which we want to perform computations is encoded into a plaintext polynomial and encrypted with a public key. 

## Important Mathematics Concepts
* Ring Theory-a ring is a set of real numbers that is equipped with addition and subtraction operations. Addition is associative and commutative, all values in R have an additive inverse (value that adds with it and obtains zero) and an additive identity of zero, multiplication is associative and distributive with respect to addition.
    * EX: Integers modulo 4: If you have the set Z/4Z={0, 1, 2, 3}, the sum of two values is the remainder when said sum is divided by 4, and the product of two values is the remainder when said product is divided by 4
* Source: https://en.wikipedia.org/wiki/Ring_(mathematics)

* Cyclotomic Polynomial-the nth cyclotomic polynoial for any positive integer n is the polynomial with integer coefficients that is a divisor of x^n - 1 and that is not a divisor of x^k -1 for any k < n. Its roots are all nth primitive roots of unity (positive number that equals 1 when raised to a positive integer power n) e^(2ipi* k/n), where k runs over the positive integers less than n and coprime to n (and i is the imaginary unit)
    * EX: For 8, the cyclotomic polynomial is x^4 + 1. x^8 -1 is evenly divisible by x^4 + 1 (the quotient is x^4 -1). No values x^k -1 for k<8 divide evenly.
* Source: https://en.wikipedia.org/wiki/Cyclotomic_polynomial

* Vandermonde Matrix-A matrix with terms of a geometric progression (sequence where each term after the first is found by multiplying the previous term by a common value) in each row. This is an (m+1) x (n+1) matrix with entries Vi,j = Xi^j, the jth power of the number xi, for all zero-based indices i and j.
    * EX: the polynomial interpolation problem is to find a polynomial that satisfies p(x0)=yo,...,p(xm)=ym for given data points (x0, y0),...,(xm , ym). The values of p(x) at the points x0, x1,...,xm are computed via matrix multiplication Va=y, where a=(a0,...,an) is the vector of coefficients and y=(y0,....,ym) = (p(x0),....,p(xm)) is the vector of values (written as column vectors)
* Source: https://en.wikipedia.org/wiki/Vandermonde_matrix

## Encoding in CKKS
* Data more often takes the form of vectors than polynomials, so we must encode our input into a polynomial.
* The degree of our polynomial degree modulus is denoted by N (a power of 2)
* We denote the mth cyclotomic polynomial (M=2N ) by (Phi_M(x)=X^N + 1).
* The plaintext space is the polynomial ring, and (xi_M) denotes the Mth root of unity (xi_M = e^{2 i pi/m})

## Vanilla Encoding
* Canonical embedding is used to code and decode our vectors.
* To decode a polynomial into a vector, we evaluate it on certain values, the roots of the cyclotomic polynomial (xi, xi^3,..., xi^{2 N-1}).
* By using sigma isomporhisms in decoding, we ensure that any vector will be uniquely encoded into its corresponding polynomial.
* Encoding a vector into the corresponding polynomial involves computing the inverse. 

### Example
* Let M = 8, N = 4 (8/2), Phi_M(X) = X^4 +1 (cyclotomic polynomial of 8) and omega = e ^ {2 i pi}/{8} = e^{i pi / 4}
* Our goal is to encode the vectors [1, 2, 3, 4] and [-1, -2, -3, -4], decode them, add and multiply their polynomial and decode it
* To decode the polynomial, evaluate it on powers of an M-th root of unity. Here xi_M =e^{i pi /4}. Once we have (xi) and (M), we can define sigma and its inverse, the decoding and encoding

### Implementation in Code
```
import numpy as np

# set parameters

M = 8
N = M//2  #division with rounding

# set xi for use in computations

xi = np.exp(2 * np.pi * 1j /M) #j is used in Python to denote complex or imaginary numbers

xi

```

```
from numpy.polynomial import Polynomial

class CKKSEncoder:
    #encodes complex vectors into polynomials

    def __init__(self, M: int):
    # xi, the Mth root of unity will be used as a basis for our computations
    self.xi=np.exp(2 * np.pi * 1j/M)
    self.M = M



    @staticmethod
    def vandermonde(xi: np.complex128, M: int) -> np.array:
    # Computes the Vandermonde matrix from a mth root of unity

         N = M//2
        matrix=[]
        # generate each row of the matrix
        for i in range(N):
            root = xi ** (2*i + 1) #raise xi to the power of 2*i (the current value) + 1. When i is 1, xi is raised to the power of 3
            row=[]

        # then store its powers
            for j in range(N):
                row.append(root ** j) #raise the root to the power of current j
            matrix.append(row)
        return matrix


    def sigma_inverse(self, b: np.array)-> Polynomial:
    # encodes vector b in a polynomial using an Mth root of unity

        # create the matrix
        A = CKKSEncoder.vandermode(self.xi, M)

        # solve the system
        coeffs = np.linalg.solve(A, b) #np.linalg.solve solves a linear matrix equation

        # output the polynomial
        p = Polynomial(coeffs)
        return p
    
    def sigma(self, p: Polynomial)-> np.array:
        # decodes a polynomial by applying it to the M-th roots of unity

        outputs=[]
        N=self.M//2

        # Apply the polynomial on the roots
        for i in range(N):
            root = self.xi ** (2 * i +1)
            output = p(root)
            outputs.append(output)
        return np.array(outputs)

```
* Let's do an example encoding a vector with real values

```
# initialize the encoder
# remember M=8
encoder=CKKSEncoder(M)

b = np.array([1, 2, 3, 4])

#let's encode the vector now
p = encoder.sigma_inverse(b)

#extract the vector we had initially from the polynomial

b_reconstructed = encoder.sigma(p)
#the values returned are very close to the initial vector

np.linalg.norm(b_reconstructed-b)

```

* We can now try to encode multiple vectors, and observe how homomorphic encryptions are performed on them.

```
m1 = np.array([1, 2, 3, 4])
m2 = np.array([1, -2, 3, -4])

p1=encoder.sigma_inverse(m1)
p2=encoder.sigma_inverse(m2)

# addition is done as so
p_add = p1 + p2

encoder.sigma(p_add)
# p1 + p2 decodes correctly to [2, 0, 6, 0]

# to perform multiplication, first define the polynomial modulus which we will use

poly_modulo = Polynomial([1, 0, 0, 0, 1])
# the above returns x^4 + 1

# now we can perform multiplication

p_mult = p1 * p2 % poly_modulo

encoder.sigma(p_mult)
# this decoded has expected results ([1, -4, 9, -16])


```

* Source: https://openmined.org/blog/ckks-explained-part-1-simple-encoding-and-decoding/#:~:text=CKKS%20allows%20us%20to%20perform,neural%20networks%2C%20and%20so%20on.


# Full Encoding and Decoding
* Encoding and decoding is integral because encryption and decryption work on polynomial rings, so it is necessary to have a way to transform vectors of real values into polynomials.
* Cannonical embedding (sigma) decodes a polynomial by evaluating it on the roots of (X^N + 1), allowing isomoprhism. 
* Because we want our encoder to output polynomials and exploit the structure of polynomial integer rings, we must modify the first vanilla encoder so it can output polynomials of the right ring.

## CKKS Encoding
* The coefficients of the polynomial of encoded values must have integer coefficients, but when we encode a vector in (mathhbb{C}^N) we do not necessarily get integer coefficients.
* Because a real polynomial is evaluated on the roots of (X^N + 1), we will also have that for any polynomial m(X) in mathcal{R}, m(xi^j)=overline{m(xi^{-j})} = m(overline{xi^{-j}})
* Any element of sigma(mathcal{R}) is actually in a space of dimension (N/2), not N, so if we use complex vectors of size (N/2) when encoding a vector in CKKS, we must expand them by copying the other half of conjugate roots. This operation is called (pi).
* Coordinate-wise random rounding is used to round a real (x) either to (lfloor x rfloor) or (lfloor x rfloor +1) with a probability that is higher the closer (x) is to (lfloor x rfloor) or (lfloor x rfloor + 1)
* Once we have coordinates (z_i), we need to round them randomly,to the higher or lower closest integer, using the "coordinate-wise random rounding", ensuring we'll have a polynomial which will have integer coordinates in the basis, and belong to sigma(mathcal{R})
* Because rounding can destroy significant numbers, we must multiply by (Delta > 0) during encoding and divide by (Delta) during decoding
* The final encoding procedure is...
    * take an element of z
    * expand it to (pi^{-1}z)
    * multiply it by Delta for precision
    * project it on sigma
    * encode it using sigma
* Decoding is simpler, from a polynomial m(X) we simply get (z= pi circ sigma(Delta^{-1}. m))

### Implementation in Code

* This is built on top of the previous CKKSEncoder class
* patch_to allows patching of objects that were previously defined, rather than redefining CKKS encoder with added methods

```
from fastcore.foundation import patch_to

@patch_to(CKKSEncoder)
def pi(self, z: np.array) -> np.array:
    # projects vector of H into C^{N/2}

    N = self.M //4
    return z[:N]

@patch_to(CKKSEncoder)
def pi_inverse(self, z: np.array) -> np.array:
    # expands vector of C^{N/2} by expanding it with its complex conjugate

    # a conjugate involves flipping the sign of the complex part of the number
    z_conjugate = z[::-1]
    z_conjugate = [np.conjugate(x) for x in z_conjugate]
    return np.concatenate([z, z_conjugate])


# now initialize the encoder with added methods
encoder = CKKSEncoder(M)

```
* Below is an example usage of pi_inverse
```
z = np.array([0, 1])
encoder.pi_inverse(z)
# output is array([0, 1, 1, 0])
```

```
@patch_to(CKKSEncoder)
def create_sigma_R_basis(self):
    self.sigma_R_basis = np.array(self.vandermonde(self.xi, self.M)).T

    # the .T creates a view of the transposed array

@patch_to(CKKSEncoder)
def __init__(self, M):
    # initialize with the basis
    self.xi = np.exp(2 * np.pi * 1j / M)
    self.M=M
    self.create_sigma_R_basis
    #using create_sigma_R_basis encodes the elements as integer polynomials
```

* We can now check that elements are encoded as integer polynomials.
```
# Here we simply take a vector whose coordinates are (1,1,1,1) in the lattice basis
coordinates = [1,1,1,1]

b = np.matmul(encoder.sigma_R_basis.T, coordinates)
# np.matmul performs matrix multiplication
```

* Now we have code for obtaining coordinates
```
@patch_to(CKKSEncoder)
def compute_basis_coordinates(self, z):
    # computes coordinates of a vector with respect to the orthogonal lattice basis
    output = np.array([np.real(np.vdot(z, b) / np.vdot(b,b)) for b in self.sigma_R_basis])
    return output
    # np.real returns the real number in complex output, np.vdot returns the dot product of two vectors

def round_coordinates(coordinates):
    # gives the integral rest
    coordinates = coordinates -np.floor(coordinates)
    return coordinates

def coordinate_wise_random_rounding(coordinates):
    #rounds coordinates randomly
    r = round_coordinates(coordinates)
    f = round_coordinates(int(coeff) for coeff in rounded_coordinates)
    return rounded_coordinates

@patch_to(CKKSEncoder)
def sigma_R_discretization(self, z):
    #Projects a vector on the lattice using coordinate wise random rounding
    coordinates = self.compute_basis_coordinates(z)
    
    rounded_coordinates = coordinate_wise_random_rounding(coordinates)
    y = np.matmul(self.sigma_R_basis.T, rounded_coordinates)
    return y
```

* Because there might be loss of precisions during rounding, we use the scale parameter (Delta to achieve a fixed level of precision)

@patch_to(CKKSEncoder)
def __init__(self, M: int, scale: float):
    # initializes with scale
    self.xi=np.exp(2 * np.pi * 1j/M)
    self.M = M
    self.create_sigma_R_basis()
    self.scale=scale

@patch_to(CKKSEncoder)
def encode(self, z: np.array) -> Polynomial:
    # encodes vector by expanding it to H, scaling it, projecting it on the lattice of sigma(R), and performing sigma inverse

    pi_z = self.pi_inverse(z)
    scaled_pi_z = self.scale * pi_z
    rounded_scale_pi_zi = self.sigma_R_discretization(scaled_pi_z)
    p = self.sigma_inverse(rounded_scale_pi_zi)

    #round due to numerical imprecision
    coef = np.round(np.real(p.coef)).astype(int)
    p = Polynomial(coef)
    return p

@patch_to(CKKSEncoder)
def decode(self, p: Polynomial) -> np.array:
    """Decodes a polynomial by removing the scale, 
    evaluating on the roots, and project it on C^(N/2)"""
    rescaled_p = p / self.scale
    z = self.sigma(rescaled_p)
    pi_z = self.pi(z)
    return pi_z

scale = 64

encoder = CKKSEncoder(M, scale)

* Source: https://openmined.org/blog/ckks-explained-part-2-ckks-encoding-and-decoding/?_gl=1*7mo2q9*_ga*NzI0NzY3NDkxLjE3NDAxNTE0NDk.*_ga_X111NXDSGH*MTc0MDE2MjcyNy4zLjEuMTc0MDE2NDQ2My4wLjAuMA..

# Encryption and Decryption
* CKKS uses approximate arithmetic, meaning once you finish computation you might get a different result than if you did the computation directly. 
* CKKS is best suited for arithmetic on real numbers, where we have approximate but close results.
## Learning with Error
* CKKS is a public key encryption scheme, where a secret key and public key are generated. Public is used for encryption, private is decryption.
* The foundation of CKKS is the _Learning With Error_ (LWE) problem, which distinguishes noisy pairs from random ones. 
* Suppose a secret key is generated and n pairs of the type is published, which can be written in matrix form. The LWE problem states it is difficult to recover the secret key from this couple, so we can use that to create a public key.
* For encryption, we take our public key (p=(-A.s + e, A)) and use it to mask our message mu. The message is hidden in the first coordinate of the ciphertext with the mask (-A.s). A is sampled uniformly so it masks mu effectively. To remove the mask, use the second coordinate of c (which only stores A) and combine it with the secret key (s) to obtain the decryption which is (mu + e). We get the original message with noise (approximate), but that should be close to the original.
* The issue with the above is that LWE can be inefficient in practice as the size of keys and complexity make it impractical.

## Ring Learning with Error
* Ring Learning with area is a variant of LWE using rings. Instead of working with vectors, we work with polynomials. Draw a, s, and e from the expression where a is sampled uniformly, s is a small secret polynomial, and e is a small noisy polynomial. This has two advantages...
 1. Key size is linear, and both private and public keys are of smaller size
 2. Multiplications are done on polynomials, therefore it can be done on a smaller time complexity than LWE's matrix vector multiplication
* RLWE results in smaller keys, faster operations, and practical use while still being secure.

## Homomorphic Operations
* As stated, we have a secret (s) and public key (p = (n,a) = (-a.s + e, a)). To encrypt a message mu, output (c = (mu +b, a)), and to decrypt it with s, evaluate (c_0 + c_1.s) which approximately gives the original message.
### Addition
* Suppose you had messages mu and mu', encrypted them into c=(c_0, c_1) and c'=(c_0', c_1'). Adding the ciphertexts together is a correct encryption of (mu + mu').
* If you add ciphertexts and decypt them you get the addition of the plaintexts, meaning you can perform additions on ecrypted data, decrypt it, and get the correct result.
### Multiplication
* Multiplication between ciphertexts is difficult, so first determine how to multiply a ciphertext with a plaintext.
* If you have a plaintext (mu), encrypted into ciphertext (c = (c_0, c_1)) and a plaintext mu', to obtain the ciphertext of the multiplication, output (c_{mult} = (mu'. c_0, mu' . c_1)). When decrypting, you get approximately the same result (with noise) as multiplying mu and mu'
* Source: https://openmined.org/blog/ckks-explained-part-3-encryption-and-decryption/?_gl=1*1vq1zvx*_ga*NzI0NzY3NDkxLjE3NDAxNTE0NDk.*_ga_X111NXDSGH*MTc0MDE2MjcyNy4zLjEuMTc0MDE2NDM0OC4wLjAuMA..

# Multiplication and Relinearization
## Ciphertext-ciphertext Multiplication
* The goal is to find operations (texttt{CMult}, texttt{DecryptMult}) such that for two ciphertexts (c, c') we have:
  * (texttt{DecryptMult}(texttt{CMult}(c, c'),s) = texttt{Decrypt}(c,s) . texttt{Decrypt}(c', s)).
* Remember that (texttt{Decrypt}(c,s) = c_0 + c_1 . s), and if we develop the expression we get...
  * (texttt{Decrypt}(c, s) . textt{Decrypt}(c',s)=(c_0 + c_1.x) . (c_0' + c_1'.s) = (c_0.c_0' + c_0.c_1' + c_0'.c_1).s + c_1.c1' . s^2 = d_0 + d_1.s + d_2.s^2) with (d_0 = c_0.c_0', d_1 = (c_0.c_1' + c_0'.c_1), d_2 = c_1.c_1')
* Evaulating (texttt{Decrypt}(c,s)= c_0+c_1.s) can be seen as a polynomial evaluation on secret key (s), and it is a polynomial of degree one of the form (c_0 + c_1.S), with (S) as the polynomial variable
* If we see the decryption operation on the product of two ciphertexts, it can be seen as the polynomial (d_0 + d_1.S + d_2.S^2) of degree 2 evaluated on the secret key (s)
* The following operations can be used for ciphertext-ciphertext multiplication
  * (texttt{CMult}(c, c') = c_{mult}= (d_0, d_1, d_2) = (c_0.c_0', c_0.c_1' + c_0'.c_1, c_1.c_1'))
  * (texttt{DecryptMult}(c_{mult}, s) = d_0 + d_1.s + d_2.s^2)
* The one issue of the above is the size of the ciphertext grows significantly, so relinearization is needed to perform multiplication without size increasing.
## Relinearization
* For multiplication, a third term is needed (the d_2 term that is used for polynomial decryption).
* Relineraization is used to find multiple polynomials ((d_0', d_1') = texttt{Relin}(c_{mult})) such that...
  * (texttt{Decrypt}((d_0', d_1'), s) = d_0'+ d_1'.s = d_0 + d_1.s + d_2.s^2 = texttt{Decrypt}(c,s).texttt{Decrypt}(c',s))
* Relinearization allows to have a polynomial couple such that once it is decrypted using the regular decryption circuit which only needs the secret key, not its square, we get the multiplication of the two underlying plaintexts.
* If relinearization is performed after each ciphertext-ciphertext multiplication, we always have ciphertexts of the same size, within the same decryption circuit.
* This can be done by providing an _evaluation key_, which computes a polynomial couple. 
* Let (evk = (-a_0.s + e_0 + s^2, a_0)), with (e_0) a small random polynomial, and (a_0) an uniformly sampled polynomial. If we apply (texttt{Decrypt}(evk, s) = e_0 + s^2 approx s^2), we see the evauation key can be used to find the square term and share said key, as RLWE makes it hard to extract.
* To prevent too large of an error term, modify the evalution key and define it as (evk=(-a.0.s + e_0 + p.s^2, a_0) (text{mod} p.q)), with (p) as a large integer and (a_0) uniformly sampled from (mathcal{R}_{p.q}). The idea is to divide by (p) to reduce the noise induced by multiplication with (d_2), and the result is....
  * (P=lfloor p^{-1}.d_2.evk rceil(text{mod } q)), which means we will divide by (p) and round to the nearest integer and work with modulo (q) instead of p.q
* To define relinearization, we need an evaluation key defined as (texttt{Relin}((d_0, d_1, d_2), evk)= (d_0,d_1) + lfloor p^{-1}.d_2.evk rceil).
* If we have two ciphertexts and want to multiply them,  the workflow is...
  1. Multiply them: (c_{mult}=texttt{CMult}(c,c')=(d_0, d_1, d_2))
  2. Relinearize it: (c_{relin}=texttt{Relin}((d_0, d_1, d_2), evk))
  3. Decrypt the output: (mu_{mult}=texttt{Decrypt}(c_{relin}, s) approx mu.mu')

* Source: https://openmined.org/blog/ckks-explained-part-4-multiplication-and-relinearization/?_gl=1*yr3dcx*_ga*NzI0NzY3NDkxLjE3NDAxNTE0NDk.*_ga_X111NXDSGH*MTc0MDQxMDgxNC43LjEuMTc0MDQxMDkyNi4wLjAuMA..

# Rescaling
* Rescaling manages noise and prevents overflow.
* CKKS works with levels, meaning there are a limited number of multiplications allowed before noise is too big to correctly decrypt output.
* When using a leveled homomorphic encryption scheme, you must know the amount of operations you'll do in advance. 
* The larger the size, the heavier the computations and the less secure your parameters are.
* The hardness of the CKKS scheme is based on the ratio (frac{N}{q}), with (N) the degree of our polynomials (EX: the size of our vectors, and (q) the coefficient modulus)
* To maintain security, increase the polynomial degree.
## Context
* If you have an initial vector of values, it is multiplied by a scale (Delta) during encoding to maintain precision.
* The underlying value contained n plaintext and ciphertext is Delta.z, so when you multiply two ciphertexts, the result is z.z'.Delta^2, which contains the square of the scale, possibly causing excess noise.
* Rescaling keeps the scale constant and reduces noise present in the ciphertext
## Vanilla Solution
* If we know we must do (L) multiplications, with a scale (Delta), we will define (q) as:
 * (q=Delta^L.q_0) with (q_0 geq Delta) which will dictate how many bits we want before the decimalpart. If we want 30 bits of decimal precision of 10 bits of integer precision, we set....
 * (Delta = 2^{30}, q_0=2^{text{ #bits integer}}. 2^{text{# bits decimal}} = 2^{10 + 30}= 2^{40})
* Once we have precision, number of multiplications, and set (q) accordingly, you define the rescaling operation by dividing and rounding ciphertext.
* EX: suppose you are at a level l so the modulo is (q_l). We have a ciphertext (c in mathcal{R}{q_l}^2). We can define the rescaling operation from level l to l-1 as
  * (RS_{l->l-1}(c)= lfloor frac{q_{l-1}}{q_l} c rceil (text{mod } q_{l-1}) = lfloor Delta^{-1} c receil (text{mod } q_{l-1})) because (q_l = Delta^l.q_0)
* Once we decrypt the product of two ciphertexts (c, c'), with underlying values (Delta.z, Delta.z') after applying rescaling we have (Delta.z.z'). Therefore the scale remains constant throughout our computations as long as we rescale after each multiplication
* Noise is reduced because we divide both the underlying plaintext values, but also the noisy part of the decryption, which is of the form (mu + e)
## Chinese Remainder Theorem
* If we have (L) coprime numbers (p_1, dots, p_L), (p=prod_{l=1}^L p_l) their product, then ring isomorphism exists.
* Instead of having (q_L = Delta^L.q_0), we choose (p_1, dots, p_L, q_0) prime numbers, with each (p_l approx Delta) and (q_0) a prime number greater than (Delta) depending on the integer precision desired, then set (q_L = prod_{l=1}^L p_l.q_0)
* When using this theorem, the rescaling operation is rewritten as...
  * (RS_{l->l-1}(c)=lfloor frac{q_{l-1}}{q_l} c rceil (text{mod } q_{l-1}) = lfloor p_l^{-1} c rceil(text{mod } q_{l-1}))
* Source: https://openmined.org/blog/ckks-explained-part-5-rescaling/?_gl=1*md509l*_ga*NzI0NzY3NDkxLjE3NDAxNTE0NDk.*_ga_X111NXDSGH*MTc0MDQxMDgxNC43LjEuMTc0MDQxMDk2Mi4wLjAuMA..