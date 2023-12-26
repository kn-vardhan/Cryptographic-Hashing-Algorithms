# import necessary libraries
from typing import List
from . import sha256, sha512


def initialize_padding(size: int) -> List[str]:
    """
    Creating inner padding and outer padding with byte values 0x36, 0x5c

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


def derived_key(key: str, version: int) -> str:
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
            key = sha256.sha256(key)
        elif version == 512:
            key = sha512.sha512(key)

        # convert key (as hex string) to binary string
        key = bin(int('0x' + key, 16))[2:]

    # Padding key with zeroes up to block size
    while len(key) != block_size:
        key += '0'

    # Final derived key from secret key
    d_key = key
    return d_key


def inner_hash(key: str, ipad: str, msg: str, version: int) -> str:
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
    d_key = derived_key(key, version)

    # XOR key with ipad
    ipad = ''.join(str(int(b) ^ int(ipad[i])) for i, b in enumerate(d_key))

    # Computing inner hash
    inner_hash_result = ''
    if version == 256:
        inner_hash_result = sha256.sha256(ipad + msg)
    elif version == 512:
        inner_hash_result = sha512.sha512(ipad + msg)

    return inner_hash_result


def outer_hash(key: str, opad: str, inner: str, version: int) -> str:
    """
    Computing outer hash
    H(K XOR opad, inner_hash)

    Args:
        key (str): secret key as bit string
        opad (str): outer pad as bit string
        inner (str): inner hash as bit string
        version (int): version of the hash function (256 or 512)

    Returns:
        str: outer hash as hex string
    """

    # Fetching derived key from key
    d_key = derived_key(key, version)

    # Converting inner hash into bit string from hex string
    inner = bin(int('0x' + inner, 16))[2:]

    # XOR key with o_pad
    opad = ''.join(str(int(b) ^ int(opad[i])) for i, b in enumerate(d_key))

    # Computing outer hash
    outer_hash_result = ''
    if version == 256:
        outer_hash_result = sha256.sha256(opad + inner)
    elif version == 512:
        outer_hash_result = sha512.sha512(opad + inner)

    return outer_hash_result


# Driver code
def hmac_sha2(key: str, message: str, version: int) -> str:
    """
    Returns:
        str: hash value of the password in hex format
    """

    # Initializing inner and outer pad vectors
    pads = initialize_padding(version)

    # Check if key is a bit string
    if not sha256.is_bit_string(key):
        key = sha256.text_to_binary(key)

    # Check if message is a bit string
    if not sha256.is_bit_string(message):
        message = sha256.text_to_binary(message)

    return outer_hash(key, pads[1], inner_hash(key, pads[0], message, version), version)
