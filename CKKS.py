import numpy as np
from numpy.polynomial import Polynomial

class CKKSEncoder:
    # used to encode complex vectors into polynomials
    def __init__(self, M: int, scale:float):
        # xi, the Mth root of unity will be used as
        # a basis for our computations
        self.xi=np.exp(2 * np.pi * 1j/M)
        # np.exp calculates the exponential for the input elements
        # the value returned is e^x
        # e is Euler's number, approximately 2.71828
        # so the above returns 2.71828^(2 * pi * i/M), i is imaginary
        self.M=M
        self.create_sigma_R_basis()
        #create_sigma_R_basis encodes elements as integer polynomials
        self.scale=scale #the scale parameter is used to ensure precision in rounding

    def encode(self, z:np.array) -> Polynomial:
        # encodes vector by expanding it to H, scaling it
        # projecting it on the lattice of sigma(R), 
        # and performing sigma inverse

        pi_z=self.pi_inverse(z) # expands vector with its complex conjugate
        scaled_pi_z=self.scale * pi_z # multiply by the scale
        rounded_scale_pi_zi=self.sigma_R_discretization(scaled_pi_z)
        p=self.sigma_inverse(rounded_scale_pi_zi) #encode vector to polynomial
        
        # round due to numerical imprecision
        coef = np.round(np.real(p.coef)).astype(int) #round only real number, convert to int
        p = Polynomial(coef)
        return p

    def decode(self, p: Polynomial) -> np.array:
        # Decodes polynomial by removing the scale,
        # evaluating on the roots, and projecting it on C^(N/2)

        rescaled_p = p/self.scale #divide to remove scale
        z=self.sigma(rescaled_p) #decodes polynomial back to vector
        pi_z=self.pi(z) # expands back the N/2 vector
        return pi_z

    @staticmethod
    def vandermonde(xi: np.complex128, M: int) -> np.array:
        # Computes the Vandermonde matrix from a mth root of unity
        N=M//2 # division with rounding
        matrix=[]
        # generate each row of the matrix
        for i in range(N):
            root=xi ** (2*i + 1) #raise xi to the power of 2*i (the current value) + 1. 
            #When i is 1, xi is raised to the power of 3
            row=[]
        # then store its powers
            for j in range(N):
                row.append(root**j) 
                # raise root to the power of current j
            matrix.append(row)
        return matrix
    
    def sigma_inverse(self, b: np.array) -> Polynomial:
        # encodes vector b in a polynomial using an Mth root of unity

        # create Matrix
        A = CKKSEncoder.vandermonde(self.xi, M)

        # solve the system
        coeffs=np.linalg.solve(A, b)
        # np.linalg.solve solves a linear matrix equation

        # output the polynomial
        p = Polynomial(coeffs)
        return p

    def sigma(self, p: Polynomial)-> np.array:
        # decodes a polynomial, applying it to the mth roots of unity
        outputs=[]
        N=self.M//2

        # Apply the polynomial on the roots
        for i in range(N):
            root = self.xi ** (2 * i+1) 
            #raise to the power of 2 times current i plus 1
            # if i is 2, raise to 6
            output=p(root) #converts output to polynomial form
            outputs.append(output) #adds the polynomial to the roots list
        return np.array(outputs) #list is converted to an array
    
    def pi(self, z:np.array) -> np.array:
        # pi is an operation used on complex vectors
        # it expands vectors of size N/2 by copying their conjugate roots

        # projects vector of H into C^{N/2}
        N = self.M //4 #produces 2, half of typical N
        return z[:N] #creates slice with half of list

    def pi_inverse(self, z:np.array)-> np.array:
        # expands vector of C^{N/2} by expanding it with its complex conjugate
        # a conjugate involves flipping the sign of the complex part of the number
        z_conjugate=z[::-1] #creates reverse-order version of initial array
        z_conjugate=[np.conjugate(x) for x in z_conjugate]
        return np.concatenate([z, z_conjugate])
        # combines original and conjugate arrays

    def create_sigma_R_basis(self):
        self.sigma_R_basis=np.array(self.vandermonde(self.xi, self.M)).T 
        # .T creates a view of the transposed array

    # this code will be used for obtaining coordinates
    def compute_basis_coordinates(self, z):
        #computes coordinates of a vector
        # with respect to orthogonal lattice basis
        output=np.array([np.real(np.vdot(z, b) / np.vdot(b,b)) 
        for b in self.sigma_R_basis])
        return output
        # np.real returns the real number in complex output
        # np.vdot returns the dot product of two vectors
    
    def round_coordinates(coordinates):
        # gives the integral rest
        coordinates=coordinates - np.floor(coordinates)
        return coordinates
        # returns the floor of the input
        # floor of array x is the largest integer i such that i<=x

    def coordinate_wise_random_rounding(coordinates):
        # rounds coordinates randomly
        r= round_coordinates(coordinates)
        f=np.array([np.random.choice([c, c-1], 1, p=[1-c, c]) for c in r])
        # np.random.choice generates a random sample from a given 1-D array

        rounded_coordinates=coordinates-f #remove the random elements to round the coordinates
        rounded_coordinates=[int(coeff) for coeff in rounded_coordinates]
        return rounded_coordinates
    
    def sigma_R_discretization(self, z):
        # Projects a vector on the lattice using coordinate wise random rounding
        coordinates=self.compute_basis_coordinates(z)
        #compute coordinates of the vector
        rounded_coordinates=coordinate_wise_random_rounding(coordinates)
        #round the coordinates
        y = np.matmul(self.sigma_R_basis.T, rounded_coordinates)
        #perform matrix multiplication between the transposed array and rounded coordinates
        return y

M=8
scale=64
encoder=CKKSEncoder(M, scale)

#next step, adding encryption-specific code