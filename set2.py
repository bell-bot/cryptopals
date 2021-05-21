## Imports
import math

## Challenge 1 ---------------------------------------------------------------------------------------------------
def challenge_1():
    plaintext = "YELLOW SUBMARINE"
    ciphertext = pkcs_7(5, plaintext)
    print(ciphertext)

def pkcs_7(block_size, plaintext):
    string_length = len(plaintext)
    
    # Get the desired string length by taking the ceil of string_len/block_size
    desired_length = block_size*math.ceil(string_length/block_size)
    print(desired_length)
    # Get the number of bytes needed for padding
    num_of_padding = desired_length - string_length
    padding_byte = "\\x{:02x}".format(num_of_padding)
    print(padding_byte)
    return plaintext + padding_byte*num_of_padding

challenge_1()