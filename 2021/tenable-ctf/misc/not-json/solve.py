#!/usr/bin/python3

import bson
from base64 import b64decode

def main():
    input = 'wAAAAAIwAB4AAABhYmNkZWZnaGppa2xtbm9wcXJzdHV2d3h5el97fQAEMQCTAAAAEDAABQAAABAxAAsAAAAQMgAAAAAAEDMABgAAABA0ABsAAAAQNQASAAAAEDYADgAAABA3AA0AAAAQOAAaAAAAEDkADgAAABAxMAAFAAAAEDExABoAAAAQMTIAAAAAABAxMwAaAAAAEDE0AAEAAAAQMTUAEgAAABAxNgAOAAAAEDE3AA0AAAAQMTgAHAAAAAAA'
    input = b64decode(input)
    input = bson.BSON(input).decode()

    print(''.join([input['0'][i] for i in input['1']]))

if __name__ == '__main__':
    main()
