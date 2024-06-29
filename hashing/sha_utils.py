"""
Utility functions for SHA hashing

Functions:
    is_bit_string(input_string: str) -> bool
    text_to_binary(input_string: str) -> str

"""

# import necessary libraries
from typing import List

def chunking(L: str, n: int) -> List[str]:
    """
    Breaking message into n-bit chunks

    Args:
        L (str): padded message
        n (int): number of bits in each chunk

    Returns:
        list(str): list of n-bit chunks
    """

    chunks = []
    for i in range(0, len(L), n):
        chunks.append(L[i: i + n])

    return chunks


def rotate_right(n: int, b: int, l: int) -> int:
    """
    Right rotate an l-bit integer n by b bits

    Args:
        n (int): 32/64-bit integer to be rotated
        b (int): number of bits to rotate
        l (int): specify the length of the integer

    Returns:
        int: rotated 32/64-bit integer
    """

    if l == 32:
        return ((n >> b) | (n << (32 - b))) & 0xffffffff
    elif l == 64:
        return ((n >> b) | (n << (64 - b))) & 0xffffffffffffffff


def is_bit_string(input_string: str) -> bool:
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


def text_to_binary(input_string: str) -> str:
    """
    Convert input string to binary string

    Args:
        input_string (str): input string

    Returns:
        str: binary string consisting of 0s and 1s
    """

    return ''.join(format(ord(char), '08b') for char in input_string)
