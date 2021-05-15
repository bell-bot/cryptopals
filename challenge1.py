import base64
import math

## IMPORTANT ################################################################################################################
## All the functions, except for the challenge ones, operate on, and return, bytes.##########################################
#############################################################################################################################

## CONSTANTS --------------------------------------------------------------------------------------------------------------##
letter_frequencies = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
}

## Challenge 1 ------------------------------------------------------------------------------------------------------------##
def challenge_1():
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    #Decode hex string to get raw bytes
    byte_string = bytes.fromhex(hex_string)
    return byte_to_base64(byte_string)

def byte_to_base64(byte_string):
    #From the byte string we can convert to base64
    return base64.b64encode(byte_string)

## Challenge 2 ------------------------------------------------------------------------------------------------------------##
def challenge_2():
    buffer1 = "1c0111001f010100061a024b53535009181c"
    buffer2 = "686974207468652062756c6c277320657965"

    #Convert both buffers to bytes
    buf1_bytes = bytes.fromhex(buffer1)
    buf2_bytes = bytes.fromhex(buffer2)

    xor = fixed_xor(buf1_bytes, buf2_bytes)
    return xor.hex()

def fixed_xor(buffer1, buffer2):
    output = bytearray()

    #Iterate over each byte, xoring them and appending them to the bytearray
    for (i,j) in zip(buffer1, buffer2):
        output.append(i^j)

    return output

## Challenge 3 ------------------------------------------------------------------------------------------------------------##
def challenge_3():
    hex_string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    
    # Convert the hex string to bytes
    byte_string = bytes.fromhex(hex_string)
    return single_byte_xor(byte_string)

def score_plaintext(plaintext):
    score = 0
    for letter in plaintext.lower():
        score += letter_frequencies.get(chr(letter), 0)

    return score

def xor_string_with_char(byte_string, character):
    xored_string = b''
    for i in byte_string:
        xored_string += bytes([i^character])

    return xored_string

def single_byte_xor(byte_string):

    #Any hex character can be the key
    possible_keys = range(256)

    #Keep track of the highest score and most likely sentence
    high_score = 0
    likely_message = ""
    key = ""

    #For every possible key, xor it with the input
    for i in possible_keys:
        message = xor_string_with_char(byte_string, i)
        score = score_plaintext(message)
        if score > high_score:
            high_score = score
            likely_message = message
            key = i

    return high_score, likely_message, key

## Challenge 4 ------------------------------------------------------------------------------------------------------------##
def challenge_4():
    #Get data from the file
    file_data = read_file_to_array("4.txt")
    return find_single_byte_xor(file_data)

def read_file_to_array(filename):
    #Open file in readmode
    f = open(filename, "r")
    #Return file data as a list of strings
    return f.readlines()

def find_single_byte_xor(file_data):

    #Keep track of the line that attracts the highest score, along with the key, ciphertext, and line_number
    high_score = 0
    plaintext = ""
    ciphertext = ""
    line_number = 0
    key = ""

    #Iterate over all lines, computing their most likely number and score
    for i in range(len(file_data)):
        byte_data = bytes.fromhex(file_data[i])
        score, message, k = single_byte_xor(byte_data)
        if score > high_score:
            high_score = score
            plaintext = message
            ciphertext = byte_data
            line_number = i
            key = k

    return high_score, plaintext, ciphertext, line_number, key

## Challenge 5 ------------------------------------------------------------------------------------------------------------##
def challenge_5():
    plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = "ICE"

    #Convert the kex and plaintext to bytes
    byte_text = bytes(plaintext, "ascii")
    byte_key = bytes(key, "ascii")

    return repeating_key_xor(byte_text, byte_key).hex()

def repeating_key_xor(bytes_text, bytes_key):

    ciphertext = b''
    current_key_index = 0
    current_key = bytes_key[current_key_index]

    for letter in bytes_text:
        ciphertext += bytes([letter^current_key])
        #Update the current key to be the next letter in the key
        current_key_index = (current_key_index+1)%len(bytes_key)
        current_key = bytes_key[current_key_index]

    return ciphertext

## Challenge 6 ------------------------------------------------------------------------------------------------------------##
def challenge_6():
    data = read_file_to_string("6.txt")

    #Decode to bytes from base 64
    byte_data = base64.b64decode(data)
    keys = breaking_repeating_key_xor(byte_data)
    #Try to decode the message
    for key in keys:
        print(key)
        print(repeating_key_xor(byte_data, bytes(key, "utf-8")).decode("utf-8"))

def hamming_distance(a,b):

    distance = 0
    # Taken from http://blog.joshuahaddad.com/cryptopals-challenges-6/
    #Create iterables using zip(), stops when shortest iterable is exhausted
    for b1, b2 in zip(a, b):
        #XOR b1 and b2
        diff = b1 ^ b2

        #Count the ones
        distance += sum([1 for bit in bin(diff) if bit == '1'])

    return distance

def read_file_to_string(filename):
    #Open file in readmode
    f = open(filename, "r")
    #Return file data as a list of strings
    return f.read()

def breaking_repeating_key_xor(byte_data):

    # For each keysize, 2-40, take the first keysize worth of bytes, the second keysize worth of bytes and find the edit distance
    # between them, normalized by keysize
    keysizes = []
    for keysize in range(2,41):

        data_blocks = [byte_data[keysize*j:keysize*(j+1)] for j in range(int(len(byte_data)/keysize))]
        dist = 0
        #Compute the pairwise edit distance
        for i in range(len(data_blocks)-1):

            segment1 = data_blocks[i]
            segment2 = data_blocks[i+1]
        
            edit_distance = hamming_distance(segment1, segment2)/keysize
            dist += edit_distance
        dist = dist/len(data_blocks)
        data = {
            'keysize': keysize,
            'edit_distance': dist
        }
        keysizes.append(data)

    #The smallest 2-3 keysizes are probably the correct keysize
    keysizes = sorted(keysizes, key = lambda data: data['edit_distance'])
    keys = []
    
    for i in range(0,3):
        keysize = keysizes[i]['keysize']
        # Break the data into blocks of length keysize
        data_blocks = [byte_data[keysize*j:keysize*(j+1)] for j in range(int(len(byte_data)/keysize))]
        
        # Transpose the blocks, i.e. make a block that is the first byte of every block, a block that is the second byte of every block
        # and so on.
        transposed_blocks = []
        for j in range(keysize):
            transposed_block = b""
            for block in data_blocks:
                transposed_block += bytes([block[j]])

            transposed_blocks.append(transposed_block)
        
        # Solve each transposed block as a single-character xor
        likely_key = ""
        for block in transposed_blocks:
            high_score, likely_message, key = single_byte_xor(block)
            likely_key += chr(key)
        keys.append(likely_key)
    return keys