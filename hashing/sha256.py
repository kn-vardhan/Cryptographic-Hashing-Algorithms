"""
This module contains the implementation of SHA-256 hashing algorithm

sha256(password: str) -> str: returns hash value of the password in hex format

Functions:
    _padding(bit_string: str) -> str
    _processing_sha256(padded_message: str) -> str
    _compression256(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, W: List[int]) -> List[int]
    b_sig0(x: int) -> int
    b_sig1(x: int) -> int
    s_sig0(x: int) -> int
    s_sig1(x: int) -> int
    sha256(password: str) -> str

"""

# import necessary libraries
from .sha_utils import *

# import necessary constants from constants package
from constants.Constants import K_sha256, init_hash_sha256

# expose only the required functions
__all__ = ['sha256']

def _padding(bit_string: str) -> str:
    """
    Pre-_processing_sha512 message by _padding
    M + 1 + K ≡ 448 mod 512

    Args:
        bit_string (str): bit string to be hashed

    Returns:
        str: padded bit string
    """

    # Appending '1' to the bit string
    pad_msg = bit_string + '1'

    # Padding with K '0' bits
    while (len(pad_msg) + 64) % 512 != 0:
        pad_msg += '0'

    # Padding message length as a 64-bit big-endian integer
    length = len(bit_string)
    pad_msg += '{0:064b}'.format(length)

    return pad_msg


def _processing_sha256(padded_message: str) -> str:
    """
    Process message in successive 512-bit chunks and produce final hash

    Args:
        padded_message (str): padded message in bits

    Returns:
        str: final hash value in hex
    """

    # Initializing hash values
    hash_vals = init_hash_sha256.copy()

    # Breaking message into 512-bit chunks
    chunks = chunking(padded_message, 512)

    # Processing each chunk using working variables
    for chunk in chunks:

        # Breaking each chunk into 32-bit big-endian words with 16 words each
        W = chunking(chunk, 32)
        W = [int(i, 2) for i in W]

        # Extending the first 16 words into the remaining 48 words of the message schedule array
        for i in range(16, 64):
            W.append((s_sig1(W[i - 2]) + W[i - 7] + s_sig0(W[i - 15]) + W[i - 16]) & 0xffffffff)

        # Initializing working variables to current hash values
        a, b, c, d, e, f, g, h = hash_vals

        # Performing the main compression function
        variable_hash = _compression256(a, b, c, d, e, f, g, h, W)

        # Adding compressed chunk to initialized current hash value
        for i in range(8):
            hash_vals[i] = (hash_vals[i] + variable_hash[i]) & 0xffffffff

    return ''.join(f'{h:08x}' for h in hash_vals)


def _compression256(a: int, b: int, c: int, d: int, e: int, f: int, g: int, h: int, W: List[int]) -> List[int]:
    """
    Main Compression Function for SHA-256

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

    for i in range(0, 64):

        ch = (e & f) ^ (~e & g)
        maj = (a & b) ^ (a & c) ^ (b & c)

        temp1 = (h + b_sig1(e) + ch + K_sha256[i] + W[i])
        temp2 = (b_sig0(a) + maj)

        # Rotating the working variables
        h, g, f = g, f, e
        e = (d + temp1) & 0xffffffff
        d, c, b = c, b, a
        a = (temp1 + temp2) & 0xffffffff

    return [a, b, c, d, e, f, g, h]


def b_sig0(x: int) -> int:
    """
    SHA-256 bit operations
    Σ(x) = (x >>> 2) XOR (x >>> 13) XOR (x >>> 22)

    Args:
        x (int): 32-bit integer

    Returns:
        int: SHA-256 bit operation
    """

    return rotate_right(x, 2, 32) ^ rotate_right(x, 13, 32) ^ rotate_right(x, 22, 32)


def b_sig1(x: int) -> int:
    """
    SHA-256 bit operations
    Σ(x) = (x >>> 6) XOR (x >>> 11) XOR (x >>> 25)

    Args:
        x (int): 32-bit integer

    Returns:
        int: SHA-256 bit operation
    """

    return rotate_right(x, 6, 32) ^ rotate_right(x, 11, 32) ^ rotate_right(x, 25, 32)


def s_sig0(x: int) -> int:
    """
    SHA-256 bit operations
    σ(x) = (x >>> 7) XOR (x >>> 18) XOR (x >> 3)

    Args:
        x (int): 32-bit integer

    Returns:
        int: SHA-256 bit operation
    """

    return rotate_right(x, 7, 32) ^ rotate_right(x, 18, 32) ^ (x >> 3)


def s_sig1(x: int) -> int:
    """
    SHA-256 bit operations
    σ(x) = (x >>> 17) XOR (x >>> 19) XOR (x >> 10)

    Args:
        x (int): 32-bit integer

    Returns:
        int: SHA-256 bit operation
    """

    return rotate_right(x, 17, 32) ^ rotate_right(x, 19, 32) ^ (x >> 10)


# Driver code
def sha256(password: str) -> str:
    """
    Generate SHA-256 hash of the input password

    Args:
        password (str): password to be hashed

    Returns:
        str: hash value of the password in hex format
    """

    # Check if input is a bit string
    if not is_bit_string(password):
        password = text_to_binary(password)

    return _processing_sha256(_padding(password))
