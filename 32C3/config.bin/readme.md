#config.bin cracker
This tool bruteforces the password of a specific flavor of `config.bin` files as described here: https://heinrichs.io/207 .  
Also it decrypt the file.  

**The *plain text* need to be a gzip file (or at least start with the magic \x1f\x8b\x08)**  
  
It is multithreaded(/processed) and relies on the correct functionality of the `multiprocessing` module.  

For configuration see the top of the file (for now).


