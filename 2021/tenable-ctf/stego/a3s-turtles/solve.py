#!/usr/bin/python3

from zipfile import *

def main():
    bits = []
    i = 128

    while i > 0:
        with ZipFile('turtles' + str(i) + '.zip') as zip:
            try:
                zip.extractall(pwd=b'0')
                print('0')
            except:
                zip.extractall(pwd=b'1')
                print('1')
        i -= 1

if __name__ == '__main__':
    main()
