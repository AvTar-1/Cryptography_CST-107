# sdes.py
# Fair us of AI tools to check errors

P10   = [3,5,2,7,4,10,1,9,8,6]
P8    = [6,3,7,4,8,5,10,9]
IP    = [2,6,3,1,4,8,5,7]
IP_INV= [4,1,3,5,7,2,8,6]
EP    = [4,1,2,3,2,3,4,1]
P4    = [2,4,3,1]

# Standard S-DES S-boxes
S0 = [
    [1,0,3,2],
    [3,2,1,0],
    [0,2,1,3],
    [3,1,3,2]
]
S1 = [
    [0,1,2,3],
    [2,0,1,3],
    [3,0,1,0],
    [2,1,0,3]
]

def permute(bits: str, table):
    return ''.join(bits[i-1] for i in table)

def left_shift(bits: str, n: int):
    return bits[n:] + bits[:n]

def xor(a: str, b: str):
    return ''.join('0' if x == y else '1' for x, y in zip(a, b))

def sbox_lookup(bits4: str, sbox):
    row = int(bits4[0] + bits4[3], 2)
    col = int(bits4[1:3], 2)
    val = sbox[row][col]
    return format(val, '02b')

def fk(bits8: str, subkey8: str):

    L = bits8[:4]
    R = bits8[4:]
    # Expand & permute R
    ER = permute(R, EP)            
    x = xor(ER, subkey8)           
    left4, right4 = x[:4], x[4:]
    s_out = sbox_lookup(left4, S0) + sbox_lookup(right4, S1)
    p4 = permute(s_out, P4)
    newL = xor(L, p4)
    return newL + R

def generate_subkeys(key10: str):
    p10 = permute(key10, P10)
    L, R = p10[:5], p10[5:]
    L1, R1 = left_shift(L,1), left_shift(R,1)
    K1 = permute(L1 + R1, P8)
    L2, R2 = left_shift(L1,2), left_shift(R1,2)
    K2 = permute(L2 + R2, P8)
    return K1, K2

def encrypt(plaintext8: str, key10: str):
    K1, K2 = generate_subkeys(key10)
    ip = permute(plaintext8, IP)
    r1 = fk(ip, K1)
    swapped = r1[4:] + r1[:4]      
    r2 = fk(swapped, K2)
    ciphertext = permute(r2, IP_INV)
    return ciphertext

def decrypt(cipher8: str, key10: str):
    K1, K2 = generate_subkeys(key10)
    ip = permute(cipher8, IP)
    r1 = fk(ip, K2)                
    swapped = r1[4:] + r1[:4]
    r2 = fk(swapped, K1)
    plaintext = permute(r2, IP_INV)
    return plaintext

# if __name__ == "__main__":
#     plaintext = "11010111"
#     key = "1010000010"
#     expected_cipher = "10101000"  # from worked example

#     ct = encrypt(plaintext, key)
#     pt = decrypt(ct, key)
#     print("Plaintext :", plaintext)
#     print("Key       :", key)
#     print("Ciphertext:", ct)
#     print("Decrypted :", pt)
#     print("Matches expected cipher? ", ct == expected_cipher)
