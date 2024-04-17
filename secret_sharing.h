#ifndef _SECRET_SHARING_H_
#include <math.h>

void slice_secret(int secret, int num_slices, int least_num_people);
int determinantOfMatrix(int mat[3][3]);
int findSolution(int **coeff);

#endif