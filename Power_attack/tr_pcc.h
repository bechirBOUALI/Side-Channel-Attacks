// MASTER-ONLY: DO NOT MODIFY THIS FILE

/*
 * Copyright (C) Telecom ParisTech
 * 
 * This file must be used under the terms of the CeCILL. This source
 * file is licensed as described in the file COPYING, which you should
 * have received as part of this distribution. The terms are also
 * available at:
 * http://www.cecill.info/licences/Licence_CeCILL_V1.1-US.txt
*/

/** \file tr_pcc.h
 *  The \b tr_pcc library, a software library dedicated to the computation of
 *  Pearson Correlation Coefficients (PCC).
 *  \author Renaud Pacalet, renaud.pacalet@telecom-paristech.fr
 *  \date 2009-07-29
 *
 * Defines a data structure and a set of functions used to compute and manage
 * Pearson Correlation Coefficients (PCC) between a floating point (float),
 * one-dimension, vector random variable and a set of floating point scalar
 * random variables.  These coefficients are a statistical tool to evaluate the
 * correlation between random variables. In this library, the vectors are
 * considered as a collection of scalar floating point random variables and each
 * component of the vectors is considered as independant. In the following,
 * vectors are denoted Z[.] and the i-th component of vector Z[.] is denoted
 * Z[i]. The formula of a PCC between the vector random variable X[.] and the
 * scalar random variable Y is:<br>
 *   PCC(X[.], Y)[.] = {E(X[.]*Y) - E(X[.])*E(Y)[.]} / {s(X[.]) * s(Y)[.]}<br>
 * where E(Z) is the expectation (average value) of random variable Z and s(Z)
 * is its unbiased standard deviation. E(Z[.])[.] is the expectation vector of
 * the vector random variable Z[.]: each component of E(Z[.])[.] is the
 * expectation of the corresponding component of Z[.]: E(Z[.])[i] = E(Z[i]).
 * Similarly, s(Z[.])[.] is the unbiased standard deviation vector of the vector
 * random variable Z[.]: s(Z[.])[i] = s(Z[i]). The product between a vector and
 * a scalar is defined as: (X[.]*Y)[i] = X[i]*Y. The PCC between a vector random
 * variable X and a scalar random variable Y is a vector defined by:<br>
 *   PCC(X[.], Y)[i] = PCC(X[i], Y)<br>
 * The \b tr_pcc library can be used to compute a set of PCCs between one vector
 * random variable (denoted X[.]), common to all PCCs, and a set of scalar
 * random variables (denoted Y0, Y1, ..., Yn-1). To compute such a set of PCCs
 * one must first initialize a PCC context (tr_pcc_init()), indicating the
 * number ny of Y random variables. Then, realizations of the random variables
 * must be accumulated into the context: first a realization of the X[.]
 * variable (tr_pcc_insert_x()), followed by realizations of each of the ny Y
 * variables (tr_pcc_insert_y()). Once a sufficient number of realizations are
 * accumulated in the PCC context, a call to tr_pcc_consolidate() computes the
 * ny PCCs. Calls to tr_pcc_get_pcc() return the different vector PCCs. Note:
 * more realizations can be accumulated after a call to tr_pcc_consolidate(),
 * another call to tr_pcc_consolidate() will take them into account altogether
 * with the previous ones and compute the new PCC values. A call to
 * tr_pcc_free() deallocates the PCC context and makes it reusable for the
 * computation of a new set of PCCs. Example of use with 10-components vectors
 * and ny=4 Y scalar variables, in which get_next_x and get_next_y are two
 * functions returning realizations of the random variables:
 * \code
 * tr_pcc_context ctx;
 * float *x, y, *pcc;
 * int i, j, nexp;
 * ...
 * ctx = tr_pcc_init(10, 4); // 10-samples traces, 4 PCCs
 * for(i = 0; i < nexp; i++) { // For experiments
 *   x = get_next_x();
 *   tr_pcc_insert_x(ctx, x);
 *   for(j = 0; j < 4; j++) { // For PCCs
 *     y = get_next_y(j);
 *     tr_pcc_insert_y(ctx, j, y);
 *     }
 *   }
 * tr_pcc_consolidate(ctx);
 * for(j = 0; j < 4; j++) { // For PCCs
 *   pcc = tr_pcc_get_pcc(ctx, j);
     printf("PCC(X[.], Y%d)[.] =", j);
 *   for(i = 0; i < 10; i++) // For samples
 *     printf(" %lf", pcc[i]);
 *   printf("\n");
 *   }
 * tr_pcc_free(ctx);
 * ctx = tr_pcc_init(100, 12); // 100-samples traces, 12 PCCs
 * ...
 * tr_pcc_free(ctx);
 * \endcode
 * \attention 
 * It is an error to break the realization insertion scheme: if you initialized
 * your PCC context for ny Y variables, first insert a realization of X[.],
 * followed by one and only one realization of each of the ny Y variables. Then,
 * insert a new realization of X[.] and ny new realizations of the ny Y
 * variables, and so on.  Consolidate only after inserting the realization of
 * the last Y variable. Do not consolidate when in an intermediate state.
 * */

#ifndef TR_PCC_H
#define TR_PCC_H

/** The data structure used to compute and manage a set of Pearson correlation
 * coefficients. */
struct tr_pcc_context_s
{
  int ny;      /**< The number of Y random variables. */
  int nr;      /**< The current number of realizations of the random variables. */
  int l;       /**< The size of the vector random variable (number of components). */
  float *rx;   /**< The last inserted realization of X. */
  float *x;    /**< The sum of the realizations of X. */
  float *x2;   /**< The sum of the squares of the realizations of X. */
  float *y;    /**< The array of the sums of the realizations of the Ys. */
  float *y2;   /**< The array of the sums of the squares of the realizations of the Ys. */
  float **xy;  /**< The array of the sums of the products between realizations of X and Ys. */
  float **pcc; /**< The array of the PCCs. */
  char state;  /**< Tracker for insertion of the realizations. */
  int cnt;     /**< Tracker for insertion of the realizations. */
  char *flags; /**< Tracker for insertion of the realizations. */
  float *tmp1; /**< Temporary trace. */
  float *tmp2; /**< Temporary trace. */
  float *tmp3; /**< Temporary trace. */
};

/** Pointer to the tr_pcc_context_s data structure. */
typedef struct tr_pcc_context_s *tr_pcc_context;

/** Initializes a PCC context.
 * \return An initialized PCC context. */
tr_pcc_context tr_pcc_init (int l,
	   /**< The length of the X[.] vector random variable (number of components). */
			    int ny
	   /**< The number of Y random variables to manage. */
  );

/** Insert a realization of X[.] in a PCC context */
void tr_pcc_insert_x (tr_pcc_context ctx, /**< The context */
		      float *x
	     /**< The realization of X[.]. */
  );

/** Inserts a new Y realization in a PCC context. */
void tr_pcc_insert_y (tr_pcc_context ctx, /**< The context */
		      int ny,
	   /**< The index of the Y random variable (0 to ctx->ny - 1). */
		      float y
		      /**< The realization of the Y random variable. */ );

/** Consolidates a set of PCCs (computes all the PCCs from the already inserted
 * realizations). */
void tr_pcc_consolidate (tr_pcc_context ctx /**< The context */ );

/** Returns a pointer to the PCC vector number NY. \return A pointer to the PCC
 * vector number NY */
float *tr_pcc_get_pcc (tr_pcc_context ctx, /**< The context */
		       int ny
		     /**< The index of the PCC to get (0 to ctx->ny - 1). */
  );

/** Closes the manager and deallocates it. */
void tr_pcc_free (tr_pcc_context ctx);

#endif /* not TR_PCC_H */
