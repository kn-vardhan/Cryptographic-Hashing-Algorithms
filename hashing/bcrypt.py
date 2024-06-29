"""
This module contains the implementation of bcrypt hashing algorithm

bcrypt(password, salt, cost) -> List[str]: returns [ctext, salt]

Functions:
    _eks_blowfish_setup(password: str, salt: str, cost: int) -> List[any]
    _expand_key(p: List[int], s: List[List[int]], salt: str, password: str) -> List[any]
    _padding(input_string: str) -> List[str]
    _crypt_output(hash_val: str, salt: str, cost: int) -> str
    is_bit_string(input_string: str) -> bool
    _text_to_binary(input_string: str) -> str
    _binary_to_base64(bit_string: str) -> str
    _base64_to_binary(base64_string: str) -> str
    bcrypt(password: str, salt: str, cost: int) -> List[str]

"""

# import necessary libraries
import base64
from copy import deepcopy
from secrets import randbits
from typing import List
from .blowfish import blowfish

# import necessary constants from constants package
from constants.Constants import P_array, S_box, BCRYPT_CTEXT

# expose only the required functions
__all__ = ['bcrypt']

def _eks_blowfish_setup(password: str, salt: str, cost: int) -> List[any]:
    """
    Generating P-array and S-boxes from password and salt

    Args:
        password (str): password to be hashed; plain-text
        salt (str): salt used for encryption, 128-bit binary string
        cost (int): cost number of iterations; 2^cost

    Returns:
        list(int): P-array
        list(list(int)): S-boxes
    """

    # Initializing P-array and S-boxes using hexadecimal digits of pi
    p = deepcopy(P_array)
    s = deepcopy(S_box)

    # Permuting P-array and S-boxes using password and salt
    temp_p, temp_s = _expand_key(p.copy(), s.copy(), salt, password)

    # Permuting with the Expensive Part of the Algorithm
    for i in range(pow(2, cost)):
        temp_p, temp_s = _expand_key(temp_p, temp_s, '0', password)
        temp_p, temp_s = _expand_key(temp_p, temp_s, '0', salt)

    return [temp_p, temp_s]


def _expand_key(p: List[int], s: List[List[int]], salt: str, password: str) -> List[any]:
    """
    Permuting P-array and S-boxes using password and salt

    Args:
        p (list(int)): P-array
        s (list(list(int))): S-boxes
        salt (str): salt used for encryption, 128-bit binary string
        password (str): password to be hashed; plain-text

    Returns:
        list(int): P-array
        list(list(int)): S-boxes
    """

    # Checking for all-zero salt value
    if salt == '0':
        salt = '0' * 128

    # Check if password is a binary string
    if not _is_bit_string(password):
        password = _text_to_binary(password)

    # Padding password to make it a multiple of 32 bits
    password = _padding(password)

    # XORing P1 to P18 with the password
    for i in range(18):
        p[i] ^= int(password[i % len(password)], 2)

    # Splitting 128-bit salt into 2 64-bit chunks
    salt_halves = [salt[:64], salt[64:]]

    # Initializing a 64-bit zero-string block
    block = '0' * 64

    # Mixing internal state into P-array
    for i in range(0, 18, 2):

        # XORing block with salt halves and encrypting
        block = bin(int(block, 2) ^ int(salt_halves[i % 2], 2))[2:]
        block = blowfish(block, p, s)

        # Splitting encrypted-block and using as new sub-keys
        p[i] = int(block[:32], 2)
        p[i + 1] = int(block[32:], 2)

    # Mixing encrypted state into S-boxes
    for i in range(4):
        for j in range(0, 256, 2):

            # XORing block with salt halves and encrypting
            block = bin(int(block, 2) ^ int(salt_halves[i % 2], 2))[2:]
            block = blowfish(block, p, s)

            # Splitting encrypted-block and using as new sub-keys
            s[i][j] = int(block[:32], 2)
            s[i][j + 1] = int(block[32:], 2)

    return [p, s]


def _padding(input_string: str) -> List[str]:
    """
    Pre-_processing_sha512 input by _padding and _chunking

    Args:
        input_string (str): input string to be padded

    Returns:
        list(str): list of padded strings each of 32 bits
    """

    # Padding input string to make it a multiple of 32 bits
    pad_msg = input_string
    if len(pad_msg) % 32 != 0:
        pad_msg += '0' * (32 - len(pad_msg) % 32)

    # Breaking padded string into chunks of 32 bits
    chunks = [pad_msg[i:i + 32] for i in range(0, len(pad_msg), 32)]

    return chunks


def _crypt_output(hash_val: str, salt: str, cost: int) -> str:
    """
    Convert the final hash into bcrypt 's crypt output format

    Args:
        hash_val (str): final hash value; binary string
        salt (str): salt used for encryption; binary string
        cost (int): cost number of iterations; 2^cost

    Returns:
        str: bcrypt output; base64 string
    """

    # Converting hash to base64 string
    hash_val = _binary_to_base64(hash_val)

    # Converting salt to base64 string
    salt = _binary_to_base64(salt)

    return '$2a$' + str(cost) + '$' + salt + hash_val


def _is_bit_string(input_string: str) -> bool:
    """
    Check if input string is a binary string

    Args:
        input_string (str): input string

    Returns:
        bool: True if input string is a binary string, False otherwise
    """

    for char in input_string:
        if char not in ['0', '1']:
            return False

    return True


def _text_to_binary(input_string: str) -> str:
    """
    Convert input string to binary string

    Args:
        input_string (str): input string

    Returns:
        str: binary string consisting of 0s and 1s
    """

    return ''.join(format(ord(char), '08b') for char in input_string)


def _binary_to_base64(bit_string: str) -> str:
    """
    Convert binary string to base64 string

    Args:
        bit_string (str): binary string to be converted to base64 string

    Returns:
        str: base64 string
    """

    byte_data = int(bit_string, 2).to_bytes((len(bit_string) + 7) // 8)
    base64_string = base64.b64encode(byte_data).decode()

    return base64_string


def _base64_to_binary(base64_string: str) -> str:
    """
    Convert base64 string to binary string

    Args:
        base64_string (str): base64 string to be converted to binary string

    Returns:
        str: binary string
    """

    byte_data = base64.b64decode(base64_string)
    bit_string = ''.join(['{0:08b}'.format(byte) for byte in byte_data])

    return bit_string


# Driver code
def bcrypt(password: str, salt: str, cost: int) -> List[str]:
    """
    Generate bcrypt hash of the given password

    Args:
        password (str): password to be hashed; plain-text
        salt (str): salt used for encryption, 128-bit binary string
        cost (int): cost number of iterations; 2^cost

    Returns:
        list(str): [ctext, salt]
    """

    if salt is None:
        salt = randbits(128)
        # Convert int salt to binary string
        salt = '{0:0128b}'.format(salt)
    else:
        # Convert base64 salt to binary string
        salt = _base64_to_binary(salt)

    # Initializing P-array and S-boxes using EksBlowfishSetup
    p, s = _eks_blowfish_setup(password, salt, cost)

    # Initializing ciphertext
    ctext = BCRYPT_CTEXT
    for i in range(64):
        ctext = blowfish(ctext, p, s)

    # Flushing out the Blowfish state
    del p
    del s

    return [_crypt_output(ctext, salt, cost), _binary_to_base64(salt)]
