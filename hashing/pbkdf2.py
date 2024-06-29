"""
This module contains the implementation of Password-Based Key Derivation Function 2 (PBKDF2)

pbkdf2(password: str, version: int, salt: str, c: int, hLen: int, dkLen: int) -> List[str]: returns hash value and salt

Functions:
    _prf(password: str, salt: str, c: int, dkLen: int, hLen: int, version: int) -> str
    pbkdf2(password: str, version: int, salt: str, c: int, hLen: int, dkLen: int) -> List[str]

"""

# import necessary libraries
from secrets import randbits
from typing import List
from .hmac_sha2 import hmac_sha2

# export only the required functions
__all__ = ['pbkdf2']

def _prf(password: str, salt: str, c: int, dkLen: int, hLen: int, version: int) -> str:
    """
    Pseudo-Random Function
    HMAC-SHA256 and HMAC-SHA512
    HMAC: Keyed-Hashing for Message Authentication
    SHA: Secure Hash Algorithm

    Args:
        password (str): password to be hash
        salt (str): salt to be added along with the hash
        c (int): iteration count
        dkLen (int): desired length of derived key
        hLen (int): length of hash value
        version (int): version of SHA to use

    Returns:
        str: hash value (derived key) of the password
    """

    # Initializing the final hashed value
    derived_key = []

    # Total sub blocks of derived key
    num_sub_blocks = dkLen // hLen

    # Computing sub-blocks of derived key using PRF
    for i in range(1, num_sub_blocks + 1):

        # convert i to 32-bit big endian integer
        _i = '{0:032b}'.format(i)

        Ui = hmac_sha2(salt + _i, password, version)

        # convert hex string Ui to binary string
        Ui = bin(int('0x' + Ui, 16))[2:]

        for j in range(1, c):
            temp = hmac_sha2(Ui, password, version)

            # convert hex string temp to binary string
            temp = bin(int('0x' + temp, 16))[2:]

            Ui = int(Ui, 2) ^ int(temp, 2)

            # convert int Ui to binary string
            Ui = '{0:0256b}'.format(Ui)

        # Appending the sub-block to the final hashed value
        derived_key.append(Ui)

    # Converting the final hashed value to binary string up to desired length
    derived_key = ''.join(derived_key)
    derived_key = derived_key[:dkLen]

    # return hex string of DK
    return hex(int(derived_key, 2))[2:]


# Driver code
def pbkdf2(password: str, version: int, salt: str, c: int, hLen: int, dkLen: int) -> List[str]:
    """
    Generate a derived key using Password-Based Key Derivation Function 2 (PBKDF2)

    Args:
        password (str): password to be hashed
        version (int): version of the hash function (256 or 512)
        salt (str): salt to be added along with the hash
        c (int): iteration count
        hLen (int): length of hash value
        dkLen (int): desired length of derived key

    Returns:
        list(str): list containing hash value and salt
    """

    if salt is None:
        salt = randbits(128)
        # Convert int salt to binary string
        salt = '{0:0128b}'.format(salt)
    else:
        # Convert hex salt to binary string
        salt = '{0:0128b}'.format(int(salt, 16))

    return [_prf(password, salt, c, dkLen, hLen, version), salt]
