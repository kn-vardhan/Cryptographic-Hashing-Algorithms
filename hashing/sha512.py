"""
This module contains the implementation of SHA-512 hashing algorithm

sha512(password: str) -> str: returns hash value of the password in hex format

Functions:
    _padding(bit_string: str) -> str
    _processing_sha512(padded_message: str) -> str
    _compression512(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, W: List[int]) -> List[int]
    b_sig0(x: int) -> int
    b_sig1(x: int) -> int
    s_sig0(x: int) -> int
    s_sig1(x: int) -> int
    sha512(password: str) -> str

"""

# import necessary libraries
from .sha_utils import *

# import necessary constants from constants package
from constants.Constants import K_sha512, init_hash_sha512

# expose only the required functions
__all__ = ['sha512']

def _padding(bit_string: str) -> str:
    """
    Pre-_processing_sha512 message by _padding
    M + 1 + K ≡ 896 mod 1024

    Args:
        bit_string (str): bit string to be hashed

    Returns:
        str: padded message
    """

    # Appending '1' to the bit string
    pad_msg = bit_string + '1'

    # Padding with K '0' bits
    length = len(pad_msg)
    while len(pad_msg) % 1024 != 896:
        pad_msg += '0'

    # Padding message as a 128-bit big-endian integer
    pad_msg += '{0:0128b}'.format(length - 1)

    return pad_msg


def _processing_sha512(padded_message: str) -> str:
    """
    Process message in successive 1024-bit chunks and produce final hash

    Args:
        padded_message (str): padded message

    Returns:
        str: final hash value
    """

    # Initializing hash values
    hash_vals = init_hash_sha512.copy()

    # Breaking message into 1024-bit chunks
    chunks = chunking(padded_message, 1024)

    # Processing each chunk using working variables
    for chunk in chunks:

        # Breaking each chunk into 64-bit big-endian words with 16 words each
        W = chunking(chunk, 64)
        W = [int(i, 2) for i in W]

        # Extending the first 16 words into the remaining 64 words of the message schedule array
        for i in range(16, 80):
            W.append((s_sig1(W[i - 2]) + W[i - 7] + s_sig0(W[i - 15]) + W[i - 16]) & 0xffffffffffffffff)

        # Initializing working variables to current hash values
        a, b, c, d, e, f, g, h = hash_vals

        # Performing the main compression function
        variable_hash = _compression512(a, b, c, d, e, f, g, h, W)

        # Adding compressed chunk to initialized current hash value
        for i in range(8):
            hash_vals[i] = (hash_vals[i] + variable_hash[i]) & 0xffffffffffffffff

    return ''.join(f'{h:08x}' for h in hash_vals)


def _compression512(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, W: List[int]) -> List[int]:
    """
    Main Compression Function for SHA-512

    Args:
        a (int): first working variable
        b (int): second working variable
        c (int): third working variable
        d (int): fourth working variable
        e (int): fifth working variable
        f (int): sixth working variable
        g (int): seventh working variable
        h (int): eighth working variable
        W (list(int)): message schedule array

    Returns:
        list(int): updated working variables
    """

    for i in range(80):

        ch = (e & f) ^ (~e & g)
        maj = (a & b) ^ (a & c) ^ (b & c)

        temp1 = (h + b_sig1(e) + ch + K_sha512[i] + W[i]) & 0xffffffffffffffff
        temp2 = (b_sig0(a) + maj) & 0xffffffffffffffff

        # Rotating the working variables
        h, g, f = g, f, e
        e = (d + temp1) & 0xffffffffffffffff
        d, c, b = c, b, a
        a = (temp1 + temp2) & 0xffffffffffffffff

    return [a, b, c, d, e, f, g, h]


def b_sig0(x: int) -> int:
    """
    SHA-512 but operations
    Σ(x) = (x >>> 28) XOR (x >>> 34) XOR (x >>> 39)

    Args:
        x (int): 64-bit integer

    Returns:
        int: SHA-512 bit operation
    """

    return rotate_right(x, 28, 64) ^ rotate_right(x, 34, 64) ^ rotate_right(x, 39, 64)


def b_sig1(x: int) -> int:
    """
    SHA-512 bit operations
    Σ(x) = (x >>> 14) XOR (x >>> 18) XOR (x >>> 41)

    Args:
        x (int): 64-bit integer

    Returns:
        int: SHA-512 bit operation
    """

    return rotate_right(x, 14, 64) ^ rotate_right(x, 18, 64) ^ rotate_right(x, 41, 64)


def s_sig0(x: int) -> int:
    """
    SHA-512 bit operations
    σ(x) = (x >>> 1) XOR (x >>> 8) XOR (x >> 7)

    Args:
        x (int): 64-bit integer

    Returns:
        int: SHA-512 bit operation
    """

    return rotate_right(x, 1, 64) ^ rotate_right(x, 8, 64) ^ x >> 7


def s_sig1(x: int) -> int:
    """
    SHA-512 bit operations
    σ(x) = (x >>> 19) XOR (x >>> 61) XOR (x >> 6)

    Args:
        x (int): 64-bit integer

    Returns:
        int: SHA-512 bit operation
    """

    return rotate_right(x, 19, 64) ^ rotate_right(x, 61, 64) ^ x >> 6


# Driver code
def sha512(password: str) -> str:
    """
    Returns:
        str: hash value of the password in hex format
    """

    # Check if input is a bit string
    if not is_bit_string(password):
        password = text_to_binary(password)

    return _processing_sha512(_padding(password))
