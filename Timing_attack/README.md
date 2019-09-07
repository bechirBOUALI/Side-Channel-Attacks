
# Timing attack against a DES software implementation


## General description

This work come in context of a lab of hardware security course presented by professor Renaud Pacalet .we will try to exploit a flaw in a DES software implementation which computation time depends on the input messages and on the secret key.

## Some notes

* For the C language version:
    * [The **des** library, dedicated to the Data Encryption Standard (DES)][DES C library]
    * [The **pcc** library, dedicated to the computation of Pearson Correlation Coefficients (PCC)][pcc C library]
    * [The **km** library, to manage the partial knowledge about a DES (Data Encryption Standard) secret key][km C library]

* `ta.c`: a C source file that you will use as a starting point for your own attack if you chose the C language.

## Directions:

### Build all executables

```bash
$ make all
```

### Acquisition phase

Run the acquisition phase:

```bash
$ ./ta_acquisition 100000
100%
Experiments stored in: ta.dat
Secret key stored in:  ta.key
Last round key (hex):
0x79629dac3cf0
``` 

This will randomly draw a 64-bits DES secret key, 100000 random 64-bits plaintexts and encipher them using the flawed DES software implementation. Each enciphering will also be accurately timed using the hardware timer of your computer. Be patient, the more acquisitions you request, the longer it takes. Two files will be generated:
* `ta.key` containing the 64-bits DES secret key, its 56-bits version (without the parity bits), the 16 corresponding 48-bits round keys and, for each round key, the eight 6-bits subkeys.
* `ta.dat` containing the 100000 ciphertexts and timing measurements.

Note: the 48-bits last round key is printed on the standard output (`stdout`), all other printed messages are sent to the standard error (`stderr`).

Note: you can also chose the secret key with:

```bash
$ ./ta_acquisition 100000 0x0123456789abcdef
```

where `0x0123456789abcdef` is the 64-bits DES secret key you want to use, in hexadecimal form.

Note: if for any reason you cannot run `ta_acquisition`, use the provided `ta.dat.example` and `ta.key.example` files, instead.

Let us look at the few first lines of `ta.dat`:

```bash
$ head -4 ta.dat
0x743bf72164b3b7bc 80017.500000
0x454ef17782801ac6 76999.000000
0x9800a7b2214293ed 74463.900000
0x1814764423289ec1 78772.500000
```

Each line is an acquisition corresponding to one of the 100000 random plaintexts. The first field on the line is the 64 bits ciphertext returned by the DES engine, in hexadecimal form. With the numbering convention of the DES standard, the leftmost character (7 in the first acquisition of the above example) corresponds to bits 1 to 4. The following one (4) corresponds to bits 5 to 8 and so on until the rightmost (c) which corresponds to bits 61 to 64. In the first acquisition of the above example, bit number 6 is set while bit number 8 is unset. Please check your understanding of this numbering convention, if you miss something here, there are very little chances that you complete the lab. The second field is the timing measurement.

### Attack phase

* The acquisition phase is over, it is now time to design a timing attack. My personal attack that I designed it's implemented in the ta.c file. 
* My approach is to compute the output of each Sbox deponding on a guess over the subkey(6 bits) and then I try to find correlation between the hamming weight of Sbox's output and the timing taking in acquisition.  

To compile and run the example application just type:

```bash
$ make ta
$ ./ta ta.dat 100000
```
## Ressources

[Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems (Paul Kocher, CRYPTO'96)]: http://www.cryptography.com/resources/whitepapers/TimingAttacks.pdf
[hwsec project]: https://gitlab.eurecom.fr/renaud.pacalet/hwsec
[introduction lecture]: http://soc.eurecom.fr/HWSec/lectures/introduction/main.pdf
[lecture on side channel attacks]: http://soc.eurecom.fr/HWSec/lectures/side_channels/main.pdf
[DES C library]: http://soc.eurecom.fr/HWSec/doc/ta/C/des_8h.html
[pcc C library]: http://soc.eurecom.fr/HWSec/doc/ta/C/pcc_8h.html
[km C library]: http://soc.eurecom.fr/HWSec/doc/ta/C/km_8h.html

<!-- vim: set tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab textwidth=0: -->
