/*
 * Copyright (C) Telecom ParisTech
 * 
 * This file must be used under the terms of the CeCILL. This source
 * file is licensed as described in the file COPYING, which you should
 * have received as part of this distribution. The terms are also
 * available at:
 * http://www.cecill.info/licences/Licence_CeCILL_V1.1-US.txt
*/

/* THIS IS NOT A REAL POWER ATTACK: it assumes that the last round key is
 * 0x0123456789ab. Your goal is to retrieve the true last round key, instead. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <math.h>

#include "utils.h"
#include "traces.h"
#include "des.h"

/* The P permutation table, as in the standard. The first entry (16) is the
 * position of the first (leftmost) bit of the result in the input 32 bits word.
 * Used to convert target bit index into SBox index (just for printed summary
 * after attack completion). */
int p_table[32] = {
  16, 7, 20, 21,
  29, 12, 28, 17,
  1, 15, 23, 26,
  5, 18, 31, 10,
  2, 8, 24, 14,
  32, 27, 3, 9,
  19, 13, 30, 6,
  22, 11, 4, 25
};

//tr_context ctx;  // Trace context (see traces.h)
int target_bit;  // Index of target bit.
int target_sbox; // Index of target SBox.
int best_guess;  // Best guess
int best_idx;    // Best argmax
float best_max;  // Best max sample value
float *dpa[64];  // 64 DPA traces
uint64_t rk;     // Last round key
float *pcc;

/* A function to allocate cipher texts and power traces, read the
 * datafile and store its content in allocated context. */
void read_datafile (char *name, int n);

/* Compute the average power trace of the traces context ctx, print it in file
 * <prefix>.dat and print the corresponding gnuplot command in <prefix>.cmd. In
 * order to plot the average power trace, type: $ gnuplot -persist <prefix>.cmd
 * */


/* Decision function: computes bit <target_bit> of L15 for all possible values
 * of the corresponding 6-bits subkey. Takes a ciphertext and returns an array
 * of 64 values (0 or 1). */


/* Apply P. Kocher's DPA algorithm based on decision function. Computes 64 DPA
 * traces dpa[0..63], best_guess (6-bits subkey corresponding to highest DPA
 * peak), best_max (height of highest DPA peak) and best_idx (index of highest
 * DPA peak). */

int main (int argc, char **argv) {
  int n; // Number of acquisitions to use
  int g; // Guess on a 6-bits subkey

  tr_pcc_context ctx;
  uint64_t r16l16; /* Output of last round, before final permutation. */
  uint64_t l16; /* Right half of r16l16. */
  uint64_t l15;
  uint64_t sbo; /* Output of SBoxes during last round. */
  uint64_t mask;
  uint64_t k, subkey, key;
  int step, step_6;
  int i,j;
  double T,maximum;
  /************************************************************************/
  /* Before doing anything else, check the correctness of the DES library */
  /************************************************************************/
  if (!des_check ()) {
    ERROR (0, -1, "DES functional test failed");
  }

  /*************************************/
  /* Check arguments and read datafile */
  /*************************************/
  /* If invalid number of arguments (including program name), exit with error
   * message. */
  if (argc != 3 && argc != 4) {
    ERROR (0, -1, "\
usage: pa FILE N [B]\n\
  FILE: name of the traces file in HWSec format\n\
  N: number of acquisitions to use\n\
  B: index of target bit in L15 (1 to 32, as in DES standard, default: 1)\n");
  }
  /* Number of acquisitions to use is argument #2, convert it to integer and
   * store the result in variable n. */
  n = atoi (argv[2]);
  if (n < 1) { // If invalid number of acquisitions.
    ERROR (0, -1, "Invalid number of acquisitions: %d (shall be greater than 1)", n);
  }
  target_bit = 1;
  /* If 3 arguments, target bit is argument #3, convert it to integer and store
   * the result in variable target_bit. */
  if (argc == 4) {
    target_bit = atoi (argv[3]);
  }
  if (target_bit < 1 || target_bit > 32) { // If invalid target bit index
    ERROR (0, -1, "Invalid target bit index: %d (shall be between 1 and 32 included)", target_bit);
  }
  // Compute index of corresponding SBox
  target_sbox = (p_table[target_bit - 1] - 1) / 4 + 1;
  /* Read power traces and ciphertexts. Name of data file is argument #1. n is
   * the number of acquisitions to use. */
  read_datafile (argv[1], n);

  /*****************************************************************************
   * Compute and print average power trace. Store average trace in file
   * "average.dat" and gnuplot command in file "average.cmd". In order to plot
   * the average power trace, type: $ gnuplot -persist average.cmd
   *****************************************************************************/

  /***************************************************************
   * Attack target bit in L15=R14 with P. Kocher's DPA technique *
   ***************************************************************/

for (i=0; i < 8; i++)
{
  step_6 += 6;
  mask = 0xf0000000 >> step;

  ctx = tr_pcc_init(800,64);

  for(j=0; j < n; j++)
  {  
    
    tr_pcc_insert_x(ctx,tr_trace (ctx, j)); // here we insert power trace

    for (k=0; k < 64 ;k++) 
    {
        r16l16 = des_ip(ct[j]);
        l16 = des_right_half(r16l16); // r15

        sbo = des_sboxes(des_e(l16) ^ (k << (48 - step_6)));
        l15 =  des_left_half(r16l16) ^ (des_n_p(sbo & mask))                   
        T = hamming_weight((l15 ^ l16))
        //printf("T = %f\n",T);
        //printf("step %d  sbo = %ld  result %lX HM= %d\n",step,sbo,(sbo & mask),hamming_weight(sbo & mask));
        //printf("hamming weight %d\n",hamming_weight(sbo & mask));
        tr_pcc_insert_y(ctx, k, T);
    }
  } 

 tr_pcc_consolidate(ctx);

 maximum = 0 ;
 subkey = 0;
 for(j = 0; j < 64; j++) 
  {
    pcc = tr_pcc_get_pcc(ctx, j);  // Get PCC(X,Yj)
    //printf("PCC(X, Y%d) = %lf\n", j, pcc);

    if (fabs(pcc) > maximum) 
      {
        maximum = fabs(pcc);
        subkey = j;
      }   
   //printf("PCC(X, Y%d) = %lf\n", j, fabs(pcc));
  }

//printf("subkey = %d & pcc =  %lf\n", subkey, maximum);

key = (key << 6) | subkey ; // generate the final key
//printf("Sbox %d  subkey= %d key= 0x%X\n",i,subkey,key);
//printf("Sbox %d  subkey= %" PRIx64 " key= 0x%" PRIx64 "\n",i,subkey,key);
tr_pcc_free(ctx);

step += 4;


 }

  fprintf(stderr, "Last round key (hex):\n");
  //printf("0x%X\n", key);
  printf("0x%012" PRIx64 "\n", key);
  /*****************************************************************************
   * Print the 64 DPA traces in a data file named dpa.dat. Print corresponding
   * gnuplot commands in a command file named dpa.cmd. All DPA traces are
   * plotted in blue but the one corresponding to the best guess which is
   * plotted in red with the title "Trace X (0xY)" where X and Y are the decimal
   * and heaxdecimal forms of the 6 bits best guess.
   *****************************************************************************/
  // Plot DPA traces in dpa.dat, gnuplot commands in dpa.cmd
  //tr_plot (ctx, "dpa", 64, best_guess, dpa);

  /*****************
   * Print summary *
   *****************/

  /*
  fprintf (stderr, "Target bit: %d\n", target_bit);
  fprintf (stderr, "Target SBox: %d\n", target_sbox);
  fprintf (stderr, "Best guess: %d (0x%02x)\n", best_guess, best_guess);
  fprintf (stderr, "Maximum of DPA trace: %e\n", best_max);
  fprintf (stderr, "Index of maximum in DPA trace: %d\n", best_idx);
  fprintf (stderr, "DPA traces stored in file 'dpa.dat'. In order to plot them, type:\n");
  fprintf (stderr, "$ gnuplot -persist dpa.cmd\n");
*/
  /*************************
   * Free allocated traces *
   *************************/
  /*
  for (g = 0; g < 64; g++) { // For all guesses for 6-bits subkey
    tr_free_trace (ctx, dpa[g]);
  }
  tr_free (ctx); // Free traces context
  */

  /********************************************
   * Print last round key to standard output. *
   ********************************************/
  
  //rk = UINT64_C(0x0123456789ab); /* 0x0123456789ab last round key. */
  /*
  fprintf(stderr, "Last round key (hex):\n");
  printf("0x%012" PRIx64 "\n", rk);

*/
  return 0; // Exits with "everything went fine" status.
}

void read_datafile (char *name, int n) {
  int tn;

  ctx = tr_init (name, n);
  tn = tr_number (ctx);
  if (tn != n) {
    tr_free (ctx);
    ERROR (, -1, "Could not read %d acquisitions from traces file. Traces file contains %d acquisitions.", n, tn);
  }
}
