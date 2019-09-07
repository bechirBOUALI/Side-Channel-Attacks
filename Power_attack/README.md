
# Differential power analysis of a DES crypto-processor


## General description

This work come in context of a lab of hardware security course presented by professor Renaud Pacalet. We will try to retrieve a DES last round key from a set of power traces. The target implementation is the hardware DES crypto-processor which architecture is depicted in the following figure:

![DES architecture]

As can be seen from the DES architecture a full encryption takes 32 cycles (in our case the secret key is input once and then never changes):

* 8 cycles to input the message to process, one byte at a time, in the IO register
* 16 cycles to compute the 16 rounds of DES, one round per cycle,
* 8 cycles to output the result, one byte at a time, from the IO register.

> Note: the DES engine could also run faster, thanks to its IO register, by parallelizing the input/output and the processing. The IO register can be loaded in parallel, 64 bits at a time or serially, one byte at a time. A throughput of one DES processing per 16 cycles could then be reached.

The DES engine runs at 32 MHz, delivering a processing power of up to 2 millions of DES encryptions per second (only one million of DES encryptions per second for this lab where I/O and processing are not parallelized).

Using this architecture, 10000 different 64 bits messages were encrypted with the same known secret key. During the encryptions the power traces were recorded by sampling the voltage drop across a small resistor inserted between the power supply and the crypto-processor. The input plain texts and the produced cipher texts were also recorded. Each power trace has been recorded 64 times and averaged in order to increase the voltage resolution. The sampling frequency of the digital oscilloscope was 20 Gs/s, but the power traces have been down-sampled by a factor of 25. Despite this quality loss it is indeed still perfectly feasible to recover the secret key. And because the traces only contain 800 points each (32 clock periods times 25 points per clock period), your attacks should run much faster than with the original time resolution (20000 points per power trace). Will you succeed in retrieving the secret key? How many power traces will you use?

## Some useful material

* The [DES standard]
* [Differential Power Analysis (Paul Kocher, Joshua Jaffe, and Benjamin Jun)]
* The [introduction lecture]
* The [lecture on side channel attacks]
* For the C language version:
    * [The **des** library, dedicated to the Data Encryption Standard (DES)][DES C library]
    * [The **traces** library, dedicated to power traces manipulations][traces C library]
    * [The **tr\_pcc** library, dedicated to the computation of Pearson Correlation Coefficients (PCC) between power traces and scalar random variables][tr_pcc C library]
    * [The **km** library, to manage the partial knowledge about a DES (Data Encryption Standard) secret key][km C library]

## Directions

### Build all executables

```bash
$ make all
```

### Acquisitions

The power traces, plaintexts, ciphertexts and secret key are available in the binary `pa.hws` file. In the following we use the term _acquisition_ to designate a record in this file. The file contains some global parameters: number of acquisitions in the file (10000), number of samples per power trace (800), 64 bits secret key and 10000 acquisitions, each made of a 64 bits plain text, the corresponding 64 bits cipher text and a power trace. Power traces are 800 samples long and span over the 32 clock periods (25 samples per clock period) of a DES operation. The following figure represents such a power trace with the time as horizontal axis and the power (instantaneous voltage) as vertical axis:

![A power trace]

Software routines are provided to read this binary file.

The `pa.key` text file contains the 64-bits DES secret key, its 56-bits version (without the parity bits), the 16 corresponding 48-bits round keys and, for each round key, the eight 6-bits sub-keys. It also contains some information about the power traces.

### Attack phase

* My approach for this attack is described as follow:
  1. extract L16 and R16 from the cipher text
  2. compute the output of Sbox deponds on L16 and a guessing on subkey(6 bits, 64 possibilities)
  3. compute L15 
  4. compute the hamming distance between L15 and L16(R15)  
  5. using the PPC to find correlation between hamming distance and power traces to find the best subkey guess.

* My attack is implemented in the pa.c file.

To run the attack.

```bash
$ make pa
$ ./pa pa.hws 10000
0xaa0acc89efd5
```


If the printed 48-bits last round key is the same as in `pa.key`, your attack works.

Once you successfully recovered the last round key, try to reduce the number of acquisitions you are using: the less acquisitions the more practical your attack.



[initial setup]: https://gitlab.eurecom.fr/renaud.pacalet/hwsec#gitlab-and-git-set-up
[DES standard]: ../doc/des.pdf
[A power trace]: ../doc/trace.png
[provided table]: ../doc/des_pa_table.pdf
[DES architecture]: ../doc/des_architecture.png
[Differential Power Analysis (Paul Kocher, Joshua Jaffe, and Benjamin Jun)]: https://42xtjqm0qj0382ac91ye9exr-wpengine.netdna-ssl.com/wp-content/uploads/2015/08/DPA.pdf
[introduction lecture]: http://soc.eurecom.fr/HWSec/lectures/introduction/main.pdf
[lecture on side channel attacks]: http://soc.eurecom.fr/HWSec/lectures/side_channels/main.pdf
[DES C library]: http://soc.eurecom.fr/HWSec/doc/pa/C/des_8h.html
[traces C library]: http://soc.eurecom.fr/HWSec/doc/pa/C/traces_8h.html
[tr_pcc C library]: http://soc.eurecom.fr/HWSec/doc/pa/C/tr__pcc_8h.html
[km C library]: http://soc.eurecom.fr/HWSec/doc/pa/C/km_8h.html
[DES python library]: http://soc.eurecom.fr/HWSec/doc/pa/python/des.html
[traces python library]: http://soc.eurecom.fr/HWSec/doc/pa/python/traces.html
[tr_pcc python library]: http://soc.eurecom.fr/HWSec/doc/pa/python/tr_pcc.html
[km python library]: http://soc.eurecom.fr/HWSec/doc/pa/python/km.html
[Hall of Fame]: http://soc.eurecom.fr/HWSec/hf_pa.html
