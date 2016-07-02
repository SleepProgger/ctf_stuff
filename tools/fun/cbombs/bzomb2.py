'''
TODO: add some encryptions stuff if i feel like it
TODO: maybe for another script: generate list of same byte block CRCs and remove those blocks
'''

import argparse
import sys
import bz2
from argparse import RawDescriptionHelpFormatter

BLOCKSIZE = 45899235


def compress(input_, output_, blocks=1):
    block = 'A' * BLOCKSIZE # 251 gives better compression ?
    compressor = bz2.BZ2Compressor(9)
    for _ in xrange(blocks):
        data = compressor.compress(block)
        output_.write("".join(data))
    syserr.write("Write real data... \n")    
    while True:
        data = input_.read(1024)
        if data is None or len(data) == 0:
            break
        data = compressor.compress(data)
        output_.write("".join(data))
    syserr.write("Flushing\n")
    output_.write("".join(compressor.flush()))
    output_.flush()
    output_.close()


def extract(input_, output_, blocks=1):
    decompressor = bz2.BZ2Decompressor()
    toskip = blocks * BLOCKSIZE
    while True:
        data = input_.read(1024)
        if data is None or len(data) == 0:
            break
        data = decompressor.decompress(data)
        if toskip >= len(data):
            toskip -= len(data)
            syserr.write("Skip %i\n" % len(data))
            continue
        if toskip > 0:
            data = data[toskip:]
            syserr.write("Skip %i\n" % toskip)
            toskip = 0
        syserr.write("Read %i\n" % len(data))
        output_.write("".join(data))
    input_.close()
    output_.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(formatter_class=RawDescriptionHelpFormatter,
                                     description='"Hides" and extracts stuff in archive bombs.', epilog="""EXAMPLES:
      # Compress the file 'test' and add 100 blocks (~4600MB) to the front of the archive.
      python bzomb2.py c -b 100 -i test > test.bz2
      # Extract
      python bzomb2.py x -b 100 -i test.bz2 > test
      
      # Compress a tar by reading from stdin.
      tar -cf - . | python bzomb2.py c -b 100 > ../self.bz2
      # Extract a tar archive and place files in directory 'bar'.
      python bzomb2.py x -b 100 -i ../self.bz2 | tar -C bar -xvf -
    """)
    parser.add_argument('type', choices=('xc'), help="eXtract or Compress")
    parser.add_argument('--blocks', '-b', default=1, type=int, help='For compressing: "bomb" blocks a 46 MB plaintext (900KB compressed).\nFor extracting: the amount of blocks to skip.')
    parser.add_argument('--input', '-i', type = argparse.FileType('r'), default = '-')
    # TODO: implement index
    # Think about how to pad the block or save the content length.
    #parser.add_argument('--index', '-i', default=-1, type=int, help='Where to insert/read our data.')
    args = parser.parse_args(sys.argv[1:])
    
    output = sys.stdout
    syserr = sys.stderr
    input_ = args.input
    
    if args.type == "c":
        compress(input_, output, args.blocks)
        
    elif args.type == "x":
        extract(input_, output, args.blocks)
