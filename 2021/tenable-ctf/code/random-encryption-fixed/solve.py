#!/usr/bin/python3

import random

CIPHERTEXT = [184, 161, 235, 97, 140, 111, 84, 182, 162, 135, 76, 10, 69, 246, 195, 152, 133, 88, 229, 104, 111, 22, 39]
CIPHERSEED = []
COMPUTEDSEEDS = []

def load_seeds():
    CIPHERSEED.append([249, 182, 79])
    CIPHERSEED.append([136, 198, 95])
    CIPHERSEED.append([159, 167, 6])
    CIPHERSEED.append([223, 136, 101])
    CIPHERSEED.append([66, 27, 77])
    CIPHERSEED.append([213, 234, 239])
    CIPHERSEED.append([25, 36, 53])
    CIPHERSEED.append([89, 113, 149])
    CIPHERSEED.append([65, 127, 119])
    CIPHERSEED.append([50, 63, 147])
    CIPHERSEED.append([204, 189, 228])
    CIPHERSEED.append([228, 229, 4])
    CIPHERSEED.append([64, 12, 191])
    CIPHERSEED.append([65, 176, 96])
    CIPHERSEED.append([185, 52, 207])
    CIPHERSEED.append([37, 24, 110])
    CIPHERSEED.append([62, 213, 244])
    CIPHERSEED.append([141, 59, 81])
    CIPHERSEED.append([166, 50, 189])
    CIPHERSEED.append([228, 5, 16])
    CIPHERSEED.append([59, 42, 251])
    CIPHERSEED.append([180, 239, 144])
    CIPHERSEED.append([13, 209, 132])

def solve():
    flag = ''
    for char in CIPHERSEED:
        for i in range(0,255):
            for j in range(0,4):
                # get copy
                test = list(char)
                # insert char at j
                test.insert(j, i)
                # check against COMPUTEDSEEDS
                if test in COMPUTEDSEEDS:
                    flag += chr(i ^ CIPHERTEXT[CIPHERSEED.index(char)])
                    break

    print(flag)


def compute_seeds():
    for i in range(0, 10000):
        random.seed(i)        
        rand_quad = []
        
        for j in range(0, 4):
            rand_quad.append(random.randint(0,255))

        COMPUTEDSEEDS.append(rand_quad)

if __name__ == '__main__':
    load_seeds()
    compute_seeds()
    solve()
