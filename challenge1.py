import base64
import math
from Crypto.Cipher import AES

#CONSTANTS

character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }

base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

#set 1
def hex_to_base64(hex_num):
    #convert to binary removing the leading two characters since we don't need them
    bin_num = bin(int(hex_num,16))[2:]

    #Get length of original string so we can add the leading zeros
    len_hex = len(hex_num)

    #Check how many zeros are missing
    missing_zeros = len_hex*4-len(bin_num)

    #Add missing zeros to front
    bin_num = "0"*missing_zeros + bin_num
    grouped_bin = []

    #Check how many groups of 6 we can make with the binary digits and how many 0's we need to append
    num_of_groups = len(bin_num)//6
    missing_digits = len(bin_num)%6
    last_digits = 6*num_of_groups
    #Add 0's to end of bin_num
    #bin_num = "0"*missing_digits+bin_num

    #Regroup digits into groups of 6
    for i in range(num_of_groups):
        sub_str = bin_num[i*6:(i*6)+6]
        grouped_bin.append(sub_str)

    #iterate through list of group bin numbers and find equivalent to int val in dict of base64 characters
    output = ""
    for i in grouped_bin:
        val = int(i,2)
        output += base64_chars[val]

    return output

#set 2
def xor(a,b):
    a1 = int(a,16)
    b1 = int(b,16)
    return hex((a1 ^ b1)).strip("L").strip("0x")

#set 3
def find_char(a):
    #convert to bytes
    a = bytes.fromhex(a)
    
    #initialize output list
    outputs = []

    for i in range(256):
        output = b""

        for byte in a:
            output += bytes([byte ^ i])

        outputs.append([output,i])
    #print(outputs)
    return score_messages(outputs)

def score_messages(msg):
    output = []
    for i in msg:
        a = i[0]
        #print(a)
        key = i[1]

        #iterate through message and count score
        score = 0
        for letter in a:

            if chr(letter) in character_frequencies.keys():
                score += character_frequencies[chr(letter)]

        data = {
            'key' : key,
            'msg' : a,
            'score' : score
        }
        output.append(data)

    scores = sorted(output,key=lambda x: x['score'],reverse=True)

    return scores[:5]

#set 4
def repeating_key_encryption(message, key):

    key_len = len(key)
    output = []

    #every letter is one byte, so we can just go through the message letter by letter
    for i in range(len(message)):
        key_letter = key[i%key_len]

        #Get numerical value for key_letter and letter of string
        num_key_letter = ord(key_letter)
        num_i = ord(message[i])

        #Apply XOR operation
        new_letter = bytes(num_key_letter ^ num_i)
        output.append(new_letter)

    hex_out = ""
    print(output)
    for i in output:
        hex_out += hex(int(i))[2:]
        
    return hex_out

#set 5

def challenge_six():
    file_data = open("6.txt", "r").read()

    #convert to bytes
    byte_data = base64.decodebytes(file_data.encode("ascii"))

    dists = []

    all_solutions = []
    
    #iterate through different keysizes
    for KEYSIZE in range(1,41):
        #for each KEYSIZE take the first KEYSIZE worth of bytes and the second KEYSIZE worth of bytes 
        part_1 = byte_data[:KEYSIZE]
        part_2 = byte_data[KEYSIZE:2*KEYSIZE]
        
        #find hamming distance between them
        dist = hamming_distance(str(part_1), str(part_2))

        #normalize by dividing dist by KEYSIZE
        dist = dist/KEYSIZE

        dists.append([dist,KEYSIZE])
        
    #sort dists by edit distance (first element in tuple)
    dists.sort()

    #Get the 3 entries from dists with the smallest edit distance
    smallest_dists = dists[:10]

    for i in smallest_dists:
        KEYSIZE = i[1]

        #Break text into blocks of KEYSIZE length
        #check how many blocks we can make
        num_of_blocks = math.ceil(len(byte_data)/KEYSIZE)

        leftover_bits = len(byte_data)%KEYSIZE

        blocks = []

        for j in range(num_of_blocks):
            blocks.append(byte_data[j*KEYSIZE:(j+1)*KEYSIZE])

        #print(blocks)

        transposed_blocks = []

        #transpose the blocks
        for j in range(KEYSIZE):
            current_block = ''
            for block in blocks:
                try:
                    current_block+=chr(block[j])
                except:
                    continue
            transposed_blocks.append(current_block)
        #solve each block as if it was a single-char XOR
        solutions = ""
        for block in transposed_blocks:
            #print(bytes(block,"ascii"))
            #convert to hex
            block = bytes.hex(bytes(block,"ascii"))
            #print(block)
            solutions+=chr(find_char(block)[0]['key'])

        all_solutions.append(solutions)

    return all_solutions
        

def hamming_distance(a,b):
    #convert to binary representation
    bin_a = ""
    bin_b = ""
    for i in a:
        bin_char = bin(ord(i))[2:]
        missing_digits = 8-len(bin_char)
        bin_char = "0"*missing_digits + bin_char
        bin_a += bin_char
    
    for j in b:
        bin_char = bin(ord(j))[2:]
        missing_digits = 8-len(bin_char)
        bin_char = "0"*missing_digits + bin_char
        bin_b += bin_char

    #if length are different pad with leading 0's
    diff = len(bin_a)-len(bin_b)

    if diff < 0:
        bin_a = "0"*abs(diff) + bin_a
    elif diff>0:
        bin_b = "0"*diff + bin_b

    #xor the bit strings
    c = int(bin_a,2) ^ int(bin_b,2)

    dist = 0

    #count numbers of 1's
    for i in bin(c)[2:]:
        if int(i)==1:
            dist+=1

    return dist

def decrypt_with_openssl(filename, key):
    data = open(filename, "r").read()

    #decode base64 encoded data
    data = base64.b64decode(data)
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(data)
    return plaintext.decode("utf-8")

def detect_AES_in_ECB(filename):
    data = open(filename).readlines()

    #convert to bytes
    byte_data = [bytes.fromhex(i) for i in data]

    #separate into blocks of 16 bytes each
    block_data = []

    for i in byte_data:
        index = 0
        block_i = []
        while index < len(i):
            block_i.append(i[index:index+16])
            index += 16
        block_data.append(block_i)

    highest = {"reps":1,
                "block":byte_data[0]}

    #check how many blocks occur several times for each ciphertext
    for i in block_data:
        blocks = {}
        for j in i:
            try:
                occurrences = blocks[j] + 1
                blocks[j] = occurrences
                if highest["reps"] < occurrences:
                    highest["reps"] = occurrences
                    highest["block"] = i
            except:
                blocks[j] = 1

        

    print(highest)
    print()