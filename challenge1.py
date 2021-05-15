import base64

## CONSTANTS ##
letter_frequencies = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
}

def hex_to_base64(hex_string):
    #Decode hex string to get raw bytes
    byte_string = bytes.fromhex(hex_string)
    #From the byte string we can convert to base64
    return base64.b64encode(byte_string)

def fixed_xor(buffer1, buffer2):
    #Convert both buffers to bytes
    buf1_bytes = bytes.fromhex(buffer1)
    buf2_bytes = bytes.fromhex(buffer2)

    output = bytearray()

    #Iterate over each byte, xoring them and appending them to the bytearray
    for (i,j) in zip(buf1_bytes, buf2_bytes):
        output.append(i^j)

    return output.hex()

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

def single_byte_xor(hex_string):

    #Convert hex string to bytes
    byte_string = bytes.fromhex(hex_string)

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

print(single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
    