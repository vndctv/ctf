# crypto/hAXOR
*Can you recover the flag.png image ?*

## The Challenge
We are presented with what appears to be an encrypted
png file, called `flag.png.enc`, and a Python script
called `xor.py`. We are tasked with decrypting the file.

## Encryption Method
Judging by the script name, `xor.py`, we're dealing with a
seemingly simple byte-for-byte XOR, and taking a look at
the code shows us this is the case:

```python
#!/usr/bin/env python3
from os import urandom
from random import randint
from pwn import xor

input_img = open("flag.png", "rb").read()
output_img = open("flag.png.enc", "wb")

key = urandom(8) + bytes([randint(0, 9)])
output_img.write(xor(input_img, key))
```

Let's break down what's happening:
1. File contents are read into `input_img`
2. A key is constructed from 8 bytes from `urandom` plus a single
   random byte using `randint`.
3. The file contents are `xor`ed against the key using `pwntools`
   and are written to `output_img`.

## Guessing the Key
If you're familiar with how XOR operations work, you know they fail
when it comes to known plaintext attacks.

Even though the first 8 bytes of the key were generated from
`/dev/urandom`, we only have to guess the last byte of the key
because all PNG files start with the same exact 8 byte file
signature:

```
The first eight bytes of a PNG file always contain the following values:

   (decimal)              137  80  78  71  13  10  26  10
   (hexadecimal)           89  50  4e  47  0d  0a  1a  0a
   (ASCII C notation)    \211   P   N   G  \r  \n \032 \n
```
*From: http://libpng.org/pub/png/spec/1.2/PNG-Rationale.html#R.PNG-file-signature*

Since we only need one more byte, and the value range is so small (0-9), we
will generate ten different PNG files, and manually check them.

## The Solution
Running the following `solver.py` will produce ten files:
```python
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
```

The flag can be found in `flag9.png`:

image