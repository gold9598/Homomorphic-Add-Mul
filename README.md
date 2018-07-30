# Homomorphic-Add-Mul
Improved performance of HE add &amp; mul using multiple thread
Implementation based on TFHE homomorphic crypto library.


you must pre-install TFHE to run the codes.

Compile options
  original.cpp  g++ original.cpp -o original -ltfhe-spqlios-fma -lpthread -std=c++11
  proposed.cpp  g++ proposed.cpp -o proposed -ltfhe-spqlios-fma -lpthread -std=c++11

Run options
  ./original <argument1> <argument2> <mode of calculation> <Number of bits for arguments>
  ./proposed <argument1> <argument2> <mode of calculation> <Number of bits for arguments>
  
Mode of calculations
  1 : Addition
  2 : Multiplication
  3,4 : It is for test...

When you want to check "real elapsed time"
  time ./original <argument1> <argument2> <mode of calculation> <Number of bits for arguments>
  
