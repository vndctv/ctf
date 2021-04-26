#!/usr/bin/python3

from pwn import xor

def main():
    ciphertext = open('flag.png.enc', 'rb').read()

    magic = bytes([137, 80, 78, 71, 13, 10, 26, 10])
    key = xor(ciphertext[0:8], magic)

    for i in range(0, 10):
        with open(f'flag{i}.png', 'wb') as flag:
            flag.write(xor(ciphertext, key + bytes([i])))

if __name__ == '__main__':
    main()