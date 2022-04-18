ED25519 signature algorithm for esp32.

The folder 'c25519' contains the original code from Daniel Beer ( https://www.dlbeer.co.nz/oss/c25519.html ) in public domain

'patches' contains some patches
- mul16.c is a optimised multiplication in F(2^255-19), using 16 bits blocks instead of 8 bits.
- mul22.c use 22 bits blocs instead of 8 bits.

- fp_mbedtls.c use mbedtls_mpi instead of standalone code for the computation of modulo order (it's not faster, but can save little space in ROM)
- rsa_mbedtls.c use mbedtls RSA 512 instead of standalone one for the computation of RSA512.

speed tests:
- mul16 is approx. 2.7 times faster than original multiplication on a esp32.
- mul22 is approx. 3.7 times faster than original multiplication on a esp32.

'experimental' folder:
- c25519b_mpi.hpp use mbedtls_mpi instead of standalone code for all the computations in F(2^255-19). It's not faster at all, even if the multiplication is hardare acceletated in ESP32...
- c25519_22b.hpp use direcly a unsigned int[12] to store with 22 bits blocs (to avoid pack22/uncpack22). It's approx 4 times faster thant original code, bu uses a little more space for a field element.

