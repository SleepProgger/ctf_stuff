# Decompression bomb related tools


bzomb2.py
-----
A stupid little script to store and extract data in/from bzip2 archive bombs.  
Each block (`-b`)  is about 900 kB compressed and produces about 46 MB uncompressed data.  

    usage: bzomb2.py [-h] [--blocks BLOCKS] [--input INPUT] {x,c}
    "Hides" and extracts stuff in archive bombs.
    positional arguments:
      {x,c}                 eXtract or Compress
    optional arguments:
      -h, --help            show this help message and exit
      --blocks BLOCKS, -b BLOCKS
                            In compresson mode: "bomb" blocks a 46 MB plaintext (900KB compressed).  
                            In extraction mode: the amount of blocks to skip.
      --input INPUT, -i INPUT
      
    EXAMPLES:
          # Compress the file 'test' and add 100 blocks (~4600MB) to the front of the archive.
          python bzomb2.py c -b 100 -i test > test.bz2
          # Extract
          python bzomb2.py x -b 100 -i test.bz2 > test
          
          # Compress a tar by reading from stdin.
          tar -cf - . | python bzomb2.py c -b 100 > ../self.bz2
          # Extract a tar archive and place files in directory 'bar'.
          python bzomb2.py x -b 100 -i ../self.bz2 | tar -C bar -xvf -


