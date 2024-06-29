"""
This module contains the implementation of HMAC-SHA2 hashing algorithm

hmac_sha2(key: str, message: str, version: int) -> str: returns hash value of the password in hex format

Functions:
    _initialize_padding(size: int) -> List[str]
    _derived_key(key: str, version: int) -> str
    _inner_hash(key: str, ipad: str, msg: str, version: int) -> str
    _outer_hash(key: str, opad: str, inner: str, version: int) -> str
    hmac_sha2(key: str, message: str, version: int) -> str

"""

# import necessary libraries
from .sha256 import sha256
from .sha512 import sha512
from .sha_utils import *


# expose only the required functions
__all__ = ['hmac_sha2']

def _initialize_padding(size: int) -> List[str]:
    """
    Creating inner _padding and outer _padding with byte values 0x36, 0x5c

    Args:
        size (int): block size of the hash function

    Returns:
        list(str): List containing i_pad and o_pad as bit strings
    """

    # Convert hexadecimal constants to bit strings and set length to block size
    # 0x5c == 01011100, 0x36 == 00110110
    i_pad_bits = '00110110'
    o_pad_bits = '01011100'

    while len(i_pad_bits) != size * 2:
        i_pad_bits += '00110110'
    while len(o_pad_bits) != size * 2:
        o_pad_bits += '01011100'

    return [i_pad_bits, o_pad_bits]


def _derived_key(key: str, version: int) -> str:
    """
    Block-sized derived key from the secret key

    Args:
        key (str): secret key as bit string
        version (int): version of the hash function (256 or 512)

    Returns:
        str: derived key as bit string of length block size
    """

    # Block size for version
    block_size = version * 2

    # Check if key is longer than block size
    if len(key) > block_size:
        if version == 256:
            key = sha256(key)
        elif version == 512:
            key = sha512(key)

        # convert key (as hex string) to binary string
        key = bin(int('0x' + key, 16))[2:]

    # Padding key with zeroes up to block size
    while len(key) != block_size:
        key += '0'

    # Final derived key from secret key
    d_key = key
    return d_key


def _inner_hash(key: str, ipad: str, msg: str, version: int) -> str:
    """
    Computing inner hash
    H(K XOR ipad, msg)

    Args:
        key (str): secret key as bit string
        ipad (str): inner pad as bit string
        msg (str): message as bit string
        version (int): version of the hash function (256 or 512)

    Returns:
        str: inner hash as hex string
    """

    # Fetching derived key from key
    d_key = _derived_key(key, version)

    # XOR key with ipad
    ipad = ''.join(str(int(b) ^ int(ipad[i])) for i, b in enumerate(d_key))

    # Computing inner hash
    inner_hash_result = ''
    if version == 256:
        inner_hash_result = sha256(ipad + msg)
    elif version == 512:
        inner_hash_result = sha512(ipad + msg)

    return inner_hash_result


def _outer_hash(key: str, opad: str, inner: str, version: int) -> str:
    """
    Computing outer hash
    H(K XOR opad, _inner_hash)

    Args:
        key (str): secret key as bit string
        opad (str): outer pad as bit string
        inner (str): inner hash as bit string
        version (int): version of the hash function (256 or 512)

    Returns:
        str: outer hash as hex string
    """

    # Fetching derived key from key
    d_key = _derived_key(key, version)

    # Converting inner hash into bit string from hex string
    inner = bin(int('0x' + inner, 16))[2:]

    # XOR key with o_pad
    opad = ''.join(str(int(b) ^ int(opad[i])) for i, b in enumerate(d_key))

    # Computing outer hash
    outer_hash_result = ''
    if version == 256:
        outer_hash_result = sha256(opad + inner)
    elif version == 512:
        outer_hash_result = sha512(opad + inner)

    return outer_hash_result


# Driver code
def hmac_sha2(key: str, message: str, version: int) -> str:
    """
    Generating HMAC-SHA2 hash value of the password

    Args:
        key (str): secret key as string
        message (str): message to be hashed
        version (int): version of the hash function (256 or 512)

    Returns:
        str: hash value of the password in hex format
    """

    # Initializing inner and outer pad vectors
    pads = _initialize_padding(version)

    # Check if key is a bit string
    if not is_bit_string(key):
        key = text_to_binary(key)

    # Check if message is a bit string
    if not is_bit_string(message):
        message = text_to_binary(message)

    return _outer_hash(key, pads[1], _inner_hash(key, pads[0], message, version), version)
