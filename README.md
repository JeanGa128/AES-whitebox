# AES-whitebox
prototype of whitebox AES in C . Luo,Lai,You

This is an implementation in C (part of my master thesis) of the design of Luo,Lai and You of white-box AES : http://ieeexplore.ieee.org/xpl/login.jsp?tp=&arnumber=6982727&url=http%3A%2F%2Fieeexplore.ieee.org%2Fxpls%2Fabs_all.jsp%3Farnumber%3D6982727

Compile wbAESGenerator.c with matrixOperations.c, then run the following program with the key you want in parameter (00 11 22 33 44 55 66 77 00 11 22 33 44 55 66 77 for example). If the format is not valid a default key will be used to construct the tables.
This should produce a file table.h, then compile wbAES.c and the resulting program can perform the encryption of one block. (The second compilation needs some resources and it might be difficult with machines with under 2GB of RAM) 
