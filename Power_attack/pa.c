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
#include "tr_pcc.h"

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

tr_context ctx;  // Trace context (see traces.h)
tr_pcc_context pcc_ctx;



/* A function to allocate cipher texts and power traces, read the
 * datafile and store its content in allocated context. */
void read_datafile (char *name, int n);


int main (int argc, char **argv) {
  int n; // Number of acquisitions to use
  //int g; // Guess on a 6-bits subkey

  //tr_pcc_context  cx;
  uint64_t r16l16; /* Output of last round, before final permutation. */
  uint64_t l16; /* Right half of r16l16. */
  uint64_t r15,l15;
  uint64_t sbo; /* Output of SBoxes during last round. */
  uint64_t mask;
  uint64_t k, subkey, key;
  int step, step_6;
  int i,j,s;
  float T,maximum;
  float *pcc;
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

  
  read_datafile (argv[1], n);


  key = 0;
  step = 0;
  step_6 = 0;

for (i=0; i < 8; i++) // loop for all sboxes
{
  step_6 += 6; 
  mask = 0xf0000000 >> step;

  pcc_ctx = tr_pcc_init(800,64);

  for(j=0; j < n; j++) // lopp for all samples 
  {  
    
    tr_pcc_insert_x(pcc_ctx,tr_trace(ctx, j)); // here we insert power trace

    for (k=0; k < 64 ;k++) 
    {
        r16l16 = des_ip(tr_ciphertext(ctx,j));
        l16 = des_right_half(r16l16); // r15

        sbo = des_sboxes(des_e(l16) ^ (k << (48 - step_6)));
        r15 = des_n_p(l16 ^ des_left_half(r16l16)) & mask ;
        l15 = (sbo & mask)  ;
        //T = hamming_weight((l15 ^ (l16 & mask))); // hamming distance $
        
        T = hamming_distance(l15,r15); // compute hamming distance between two states 
        //printf("T = %f\n",T);
        //printf("step %d  sbo = %ld  result %lX HM= %d\n",step,sbo,(sbo & mask),hamming_weight(sbo & mask));
        //printf("hamming weight %d\n",hamming_weight(sbo & mask));
        tr_pcc_insert_y(pcc_ctx, k, T);
    }

  } 

 tr_pcc_consolidate(pcc_ctx);

 maximum = 0 ;
 subkey = 0;
 for(j = 0; j < 64; j++) 
  {
    pcc = tr_pcc_get_pcc(pcc_ctx, j);  // Get PCC(X,Yj)
    //printf("PCC(X, Y%d) = %lf\n", j, pcc);
    float max = 0;
    for (s = 600; s < 700 ; s++)
    {
      //printf(" pcc[s] = %lf \n", pcc[s]);
      if (fabs(pcc[s]) > max)
      {
        max = fabs(pcc[s]); // find the pick of each pcc 
      }
    }
    //printf(" max 1 %lf\n",max);

    if (max >= maximum) 
      {
        maximum = max;
        subkey = j;
      }   

  }

//printf("subkey = %d & pcc =  %lf\n", subkey, maximum);

key = (key << 6) | subkey ; // generate the final key

tr_pcc_free(pcc_ctx);

step += 4;

 }

  fprintf(stderr, "Last round key (hex):\n");
  //printf("0x%X\n", key);
  printf("0x%012" PRIx64 "\n", key);

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
