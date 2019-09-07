		/*
 * Copyright (C) Telecom ParisTech
 * 
 * This file must be used under the terms of the CeCILL. This source
 * file is licensed as described in the file COPYING, which you should
 * have received as part of this distribution. The terms are also
 * available at:
 * http://www.cecill.info/licences/Licence_CeCILL_V1.1-US.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <pcc.h>
#include <math.h>


#include "utils.h"
#include "des.h"
#include "km.h"

uint64_t *ct; /* Array of cipher texts. */
double *t; /* Array of timing measurements. */

/* Allocate arrays <ct> and <t> to store <n> cipher texts and timing
 * measurements. Open datafile <name> and store its content in global variables
 * <ct> and <t>. */
void read_datafile(char *name, int n);

int main(int argc, char **argv) {
  int n; /* Required number of experiments. */
  uint64_t r16l16; /* Output of last round, before final permutation. */
  uint64_t l16; /* Right half of r16l16. */
  uint64_t sbo; /* Output of SBoxes during last round. */
  uint64_t mask;
  double sum, pcc, T, maximum, w; /* Sum of timing measurements. */
  int i; /* Loop index. */
  int j;
  uint64_t k, subkey, key;
  int step, step_6;
  pcc_context *ctx;

  /************************************************************************/
  /* Before doing anything else, check the correctness of the DES library */
  /************************************************************************/
  if(!des_check()) {
    ERROR(0, -1, "DES functional test failed");
  }

  /*************************************/
  /* Check arguments and read datafile */
  /*************************************/
  /* If invalid number of arguments (including program name), exit with error
   * message. */
  if(argc != 3) {
    ERROR(0, -1, "usage: ta <datafile> <nexp>\n");
  }
  /* Number of experiments to use is argument #2, convert it to integer and
   * store the result in variable n. */
  n = atoi(argv[2]);
  if(n < 1) { /* If invalid number of experiments. */
    ERROR(0, -1, "number of experiments to use (<nexp>) shall be greater than 1 (%d)", n);
  }
  /* Read data. Name of data file is argument #1. Number of experiments to use is n. */
  read_datafile(argv[1], n);
  /*****************************************************************************
   * Compute the Hamming weight of output of first (leftmost) SBox during last *
   *****************************************************************************/
 

  key = 0;
  step = 0;
  step_6 = 0;

for (i=0; i < 8; i++)
{

  step_6 += 6;
  mask = 0xf0000000 >> step;


  ctx = pcc_init(64);

  for(j=0; j < n; j++)
  {  
  	
    pcc_insert_x(ctx,t[j]);

    for (k=0; k < 64 ;k++) 
    {
    	r16l16 = des_ip(ct[j]);
        l16 = des_right_half(r16l16);
        sbo = des_sboxes(des_e(l16) ^ (k << (48 - step_6)));
        T = hamming_weight((sbo & mask)) ; //UINT64_C
        pcc_insert_y(ctx, k, T);
    }
  } 

 pcc_consolidate(ctx);

 maximum = 0 ;
 subkey = 0;
 for(j = 0; j < 64; j++) 
  {
    pcc = pcc_get_pcc(ctx, j);  // Get PCC(X,Yj)
    if (fabs(pcc) >= maximum) 
    	{
    		maximum = fabs(pcc);
    		subkey = j;
    	}  	
  }

key = (key << 6) | subkey ; // generate the final key
pcc_free(ctx);

step += 4;


 }

  /************************
   * Print last round key *
   ************************/
  fprintf(stderr, "Last round key (hex):\n");
  printf("0x%012" PRIx64 "\n", key);

  free(ct); /* Deallocate cipher texts */
  free(t); /* Deallocate timings */
  return 0; /* Exits with "everything went fine" status. */
}

void read_datafile(char *name, int n) {
  FILE *fp; /* File descriptor for the data file. */
  int i; /* Loop index */

  /* Open data file for reading, store file descriptor in variable fp. */
  fp = XFOPEN(name, "r");

  /* Allocates memory to store the cipher texts and timing measurements. Exit
   * with error message if memory allocation fails. */
  ct = XCALLOC(n, sizeof(uint64_t));
  t = XCALLOC(n, sizeof(double));

  /* Read the n experiments (cipher text and timing measurement). Store them in
   * the ct and t arrays. Exit with error message if read fails. */
  for(i = 0; i < n; i++) {
    if(fscanf(fp, "%" PRIx64 " %lf", &(ct[i]), &(t[i])) != 2) {
      ERROR(, -1, "cannot read cipher text and/or timing measurement");
    }
  }
}
