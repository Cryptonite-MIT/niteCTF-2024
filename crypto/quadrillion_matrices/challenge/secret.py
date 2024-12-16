from sage.all import *
from sympy import legendre_symbol
import random
def is_diagonalizable(matrix):
    """
    Checks if a matrix is diagonalizable over GF(p).
    
    Args:
        matrix (Matrix): A SageMath matrix over GF(p).
    
    Returns:
        bool: True if the matrix is diagonalizable, False otherwise.
        str: Reason if not diagonalizable.
    """
    if not matrix.is_square():
        return False, "The matrix is not square."
    min_poly = matrix.minimal_polynomial()
    if min_poly.is_irreducible():
        return False, "Minimal polynomial is irreducible, so the matrix is not diagonalizable."
    roots = min_poly.roots(multiplicities=True)
    for eigenvalue, alg_mult in roots:
        eigenspace_matrix = matrix - eigenvalue * identity_matrix(matrix.nrows())
        geom_mult = eigenspace_matrix.kernel().dimension()
        if alg_mult != geom_mult:
            return False, f"Eigenvalue {eigenvalue} has algebraic multiplicity {alg_mult} but geometric multiplicity {geom_mult}."
    return True, "The matrix is diagonalizable."
def get_random_matrix(n, p):
    A = []
    for x in range(n):
        row = []
        for y in range(n):
            row.append(random.randrange(2, p))
        A.append(row)
    matrix = Matrix(GF(p), A)
    return matrix
def gen_matrix(p):
    while True:
        bhai = get_random_matrix(2, p)
        if is_diagonalizable(bhai) and bhai.is_invertible():
            QR = bhai**8
            NQR = bhai**11
            symbol1 = QR**((p-1)//2)
            symbol2 = NQR**((p-1)//2)
            if legendre_symbol(bhai.det(), p) == 1 and symbol1 == identity_matrix(symbol1.nrows()) and symbol2 != identity_matrix(symbol2.nrows()):
                break
    return bhai