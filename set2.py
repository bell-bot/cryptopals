## Imports
import math
from set1 import read_file_to_string
from Crypto.Cipher import AES
import base64

## Challenge 9 ---------------------------------------------------------------------------------------------------
def challenge_9():
    plaintext = "YELLOW SUBMARINE"
    ciphertext = pkcs_7(5, plaintext)
    print(ciphertext)

def pkcs_7(block_size, plaintext):
    string_length = len(plaintext)
    
    # Get the desired string length by taking the ceil of string_len/block_size
    desired_length = block_size*math.ceil(string_length/block_size)

    # Get the number of bytes needed for padding
    num_of_padding = desired_length - string_length
    padding_byte = bytes([num_of_padding])

    return plaintext + padding_byte*num_of_padding

## Challenge 10 --------------------------------------------------------------------------------------------------
def challenge_10():
    
    # Get the file data and save it to a string
    file_data = read_file_to_string("10.txt")

    # Convert file_data to bytes
    file_data = base64.b64decode(file_data)

    # Define IV to be of length 8 bytes and all 0
    iv = b'\x00'*AES.block_size

    key = b'YELLOW SUBMARINE'

    print(cbc_mode_decrypt(file_data, key, iv))

    test_sentence = b'Please work I am begging you'

    ciphertext = cbc_mode_encrypt(test_sentence, iv, key)

    plaintext = cbc_mode_decrypt(ciphertext, key, iv)

    # I don't remove the added padding so just check if the plaintext (i.e. text with padding) contains the test sentence
    assert (test_sentence in plaintext)

def cbc_mode_encrypt(byte_string, iv, key):

    # Pad the string to be of length that is a multiple of the block size
    padded_string = pkcs_7(AES.block_size, byte_string)

    # Define empty string for ciphertext
    ciphertext = b''

    previous_block = iv

    # Iterate through all blocks, xoring with the iv and ecb encrypting them
    for i in range(0, len(padded_string), AES.block_size):

        block = padded_string[i: i + AES.block_size]

        # Step 1: XOR
        cipherblock = xor_bytes(block, previous_block)

        # Update previous block
        encrypted_block = ecb_encrypt(cipherblock, key)

        # ecb encrypt the block
        ciphertext += encrypted_block

        previous_block = encrypted_block

    return ciphertext

def cbc_mode_decrypt(ciphertext, key, iv):

    plaintext = b""

    previous_block = iv

    # Iterate through all blocks, in reverse order
    for i in range(0, len(ciphertext), AES.block_size):
        block = ciphertext[i: i + AES.block_size]

        # Decrypt the block
        decrypted = ecb_decrypt(block, key)
        
        # XOR with the previous block, or the IV if there are no more blocks
        plaintext += xor_bytes(decrypted, previous_block)

        # Update previous block
        previous_block = block

    return plaintext

def ecb_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def ecb_decrypt(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)

def xor_bytes(string_1,string_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(string_1, string_2)])

if __name__ == '__main__':
    challenge_10()