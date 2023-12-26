# import necessary libraries
from copy import deepcopy
from typing import List

# import necessary constants from constants package
from constants.Constants import P_array, S_box, BLOWFISH_KEY


def initialize_blowfish(key: str) -> List[any]:
    """
    Generate P-array and S-boxes from key

    Args:
        key (str): key to be used for encryption

    Returns:
        list(int): P-array
        list(list(int)): S-boxes
    """

    # Initializing P-array and S-boxes
    p = deepcopy(P_array)
    s = deepcopy(S_box)

    # XORing P1 to P18 with the key
    for i in range(18):
        p[i] ^= key[i % len(key)]

    # Initializing a 64-bit zero-string
    zero_string = '0' * 64

    # Updating P-array
    for i in range(0, 18, 2):

        # Encrypting the zero-string
        enc_string = encrypt_ecb(padding(zero_string), p, s)

        # Splitting output into L, R
        L = enc_string[:32]
        R = enc_string[32:]

        # Replacing P2i with L and P2i+1 with R
        p[i] = int(L, 2)
        p[i + 1] = int(R, 2)

        # Updating zero-string with encrypted-string
        zero_string = enc_string

    # Updating S-boxes
    for i in range(4):
        for j in range(0, 256, 2):

            # Encrypting the zero-string
            enc_string = encrypt_ecb(padding(zero_string), p, s)

            # Splitting output into L, R
            L = enc_string[:32]
            R = enc_string[32:]

            # Replacing S-boxes
            s[i][j] = int(L, 2)
            s[i][j + 1] = int(R, 2)

            # Updating zero-string with encrypted-string
            zero_string = enc_string

    return [p, s]


def padding(msg_bit_string: str) -> List[str]:
    """
    Pre-processing message by padding and chunking
    Padding message to make it a multiple of 64 bits

    Args:
        msg_bit_string: message to be encrypted in bits

    Returns:
        list(str): list of padded messages each of 64 bits
    """

    # Padding message to make it a multiple of 64 bits
    pad_msg = msg_bit_string
    if len(pad_msg) % 64 != 0:
        pad_msg = pad_msg.ljust(len(pad_msg) + (64 - len(pad_msg) % 64), '0')

    # Breaking message into 64-bit chunks
    chunks = [pad_msg[i: i + 64] for i in range(0, len(pad_msg), 64)]

    return chunks


def encrypt_ecb(padded_msgs: List[str], p: List[int], s: List[List[int]]) -> str:
    """
    Encrypt message using Blowfish algorithm

    Args:
        padded_msgs (list(str)): list of padded messages in bits
        p (list(int)): P-array
        s (list(list(int))): S-boxes

    Returns:
        str: encrypted message as a hex string
    """

    # Initializing final cipher
    cipher = ''

    # Encrypting each padded message
    for pad_msg in padded_msgs:

        # Splitting message into two halves L and R
        # Each with 32-bit bit strings
        L = pad_msg[:32]
        R = pad_msg[32:]

        # 16 rounds of fiestel function
        for i in range(16):
            L = bin(int(L, 2) ^ p[i])[2:].zfill(32)
            L1 = fiestel_function(L, s)
            R = bin(int(R, 2) ^ int(L1, 2))[2:].zfill(32)

            # Swapping left half and right half 32-bit blocks
            L, R = R, L

        # Post-processing L, R and generating cipher
        cipher += post_process(L, R, p)

    return cipher


def fiestel_function(L: str, s: List[List[int]]) -> str:
    """
    Dividing 32-bit L into 4 8-bit blocks and performing S-box substitutions

    Args:
        L (str): bit string of left half after XORing with Pi
        s (list(list(int))): S-boxes

    Returns:
        str: 32-bit fiestel bit string
    """

    # Chunking L into 4 8-bit blocks
    chunks = [L[i: i + 8] for i in range(0, len(L), 8)]

    # Performing S-box substitutions
    output = s[0][int(chunks[0], 2)]

    # Addition with second S-box modulo 2^32
    output = (output + s[1][int(chunks[1], 2)]) % pow(2, 32)

    # XOR with third S-box
    output = output ^ s[2][int(chunks[2], 2)]

    # Addition with fourth S-box modulo 2^32
    output = (output + s[3][int(chunks[3], 2)]) % pow(2, 32)

    # Converting fiestel output to 32-bit bit string
    output = bin(output)[2:].zfill(32)

    return output


def post_process(L: str, R: str, p: List[int]) -> str:
    """
    Processing final bit strings after fiestel network

    Args:
        L (str): bit string of left half after 16 rounds
        R (str): bit string of right half after 16 rounds
        p (list(int)): P-array

    Returns:
        str: final 64-bit cipher as a bit string
    """

    # Swapping L and R after 16-round network
    L, R = R, L

    # XORing with remaining Pi
    L = bin(int(L, 2) ^ p[17])[2:].zfill(32)
    R = bin(int(R, 2) ^ p[16])[2:].zfill(32)

    # Fetching final cipher from L and R
    cipher = L + R

    return cipher


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


# Driver code
def blowfish(message: str, p=None, s=None) -> str:
    """
    Encrypt message using Blowfish algorithm

    Args:
        message (str): message to be encrypted
        p (list(int)): P-array; default None
        s (list(list(int))): S-boxes; default None

    Returns:
        str: encrypted message as binary string
    """

    if p is None or s is None:
        # Generating P-array and S-boxes from key
        p, s = initialize_blowfish(BLOWFISH_KEY)

    # Check if message is a binary string
    if not is_bit_string(message):
        message = text_to_binary(message)

    # Encrypting message
    encrypted_msg = encrypt_ecb(padding(message), p, s)

    # Flushing P-array and S-boxes
    del p
    del s

    return encrypted_msg
