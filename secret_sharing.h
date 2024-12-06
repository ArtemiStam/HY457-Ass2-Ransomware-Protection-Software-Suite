#ifndef _SECRET_SHARING_H_
#include <math.h>

/* Create num_slices shares of the secret so that at least least_num_people can access the secret*/
void slice_secret(int secret, int num_slices, int least_num_people);
/* Solve the system of linear equations with the specified coefficients */
int solve_system(int **coeff);

#endif