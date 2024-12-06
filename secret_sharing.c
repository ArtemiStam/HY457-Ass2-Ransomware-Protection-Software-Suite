#include "secret_sharing.h"
#include "scanner.h"

void slice_secret(int secret, int num_slices, int least_num_people) {
    int polunomial_degree = least_num_people - 1;
    int *coefficients;
    int i, j, f_x;
    time_t t = time(NULL);
    struct tm date = *localtime(&t);

    printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Generating shares for key '%d'\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, secret);
    
    coefficients = malloc(sizeof(int)*polunomial_degree); // Malloc space for all the coefficients
    if (coefficients == NULL)
    {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    srand(time(0)); //seed the random number generator
    for (i = 0; i < polunomial_degree; i++) //generate random coefficients
    {
        coefficients[i] = (rand() % 100) + 1; //coefficient is a random number from 1 to 100
    }
    
    printf("\n");
    for (i = 1; i <= num_slices; i++) //for every slice we want
    {
        f_x = 0;
        /* Calculate f_i = coef1*(i^polunomial_degree) + coef2*(i^(polunomial_degree-1)) + ... + secret */
        for (j = 1; j <= polunomial_degree; j++) //add every coefficient in function f_x
        {
            f_x += coefficients[j-1]*pow(i, j);
        }
        f_x += secret; //add secret to the function

        printf("(%d, %d)\n", i, f_x);
    }
    
    free(coefficients);
}
 
int solve_system(int **coeff) {
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    int a, b, c;
    // Make 2d arrays based on Cramer's rules
    int d[3][3]  = {{coeff[0][0], coeff[0][1], coeff[0][2]}, {coeff[1][0], coeff[1][1], coeff[1][2]}, {coeff[2][0], coeff[2][1], coeff[2][2]}};
    int d1[3][3] = {{coeff[0][3], coeff[0][1], coeff[0][2]}, {coeff[1][3], coeff[1][1], coeff[1][2]}, {coeff[2][3], coeff[2][1], coeff[2][2]}};
    int d2[3][3] = {{coeff[0][0], coeff[0][3], coeff[0][2]}, {coeff[1][0], coeff[1][3], coeff[1][2]}, {coeff[2][0], coeff[2][3], coeff[2][2]}};
    int d3[3][3] = {{coeff[0][0], coeff[0][1], coeff[0][3]}, {coeff[1][0], coeff[1][1], coeff[1][3]}, {coeff[2][0], coeff[2][1], coeff[2][3]}};
 
    // Find determinant of matrices d, d1, d2, d3
    double D  = d[0][0] * (d[1][1] * d[2][2] - d[2][1] * d[1][2]) - d[0][1] * (d[1][0] * d[2][2] - d[1][2] * d[2][0]) + d[0][2] * (d[1][0] * d[2][1] - d[1][1] * d[2][0]); // find determinant of matrix d
    double D1 = d1[0][0] * (d1[1][1] * d1[2][2] - d1[2][1] * d1[1][2]) - d1[0][1] * (d1[1][0] * d1[2][2] - d1[1][2] * d1[2][0]) + d1[0][2] * (d1[1][0] * d1[2][1] - d1[1][1] * d1[2][0]); // find determinant of matrix d1
    double D2 = d2[0][0] * (d2[1][1] * d2[2][2] - d2[2][1] * d2[1][2]) - d2[0][1] * (d2[1][0] * d2[2][2] - d2[1][2] * d2[2][0]) + d2[0][2] * (d2[1][0] * d2[2][1] - d2[1][1] * d2[2][0]); // find determinant of matrix d2
    double D3 = d3[0][0] * (d3[1][1] * d3[2][2] - d3[2][1] * d3[1][2]) - d3[0][1] * (d3[1][0] * d3[2][2] - d3[1][2] * d3[2][0]) + d3[0][2] * (d3[1][0] * d3[2][1] - d3[1][1] * d3[2][0]);// find determinant of matrix d3
 
    if (D != 0) { // Found unique solution
        a = D1 / D;
        b = D2 / D;
        c = D3 / D; 
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Computed that a=%d and b=%d\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, a, b);
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Encryption key is: \033[0;34m%d\033[0m\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, c);
        return 1; // unique solution found
    }

    return 0; //something went wrong(there is no unique solution)
}