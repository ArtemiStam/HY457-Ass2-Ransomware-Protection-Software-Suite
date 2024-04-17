#include "secret_sharing.h"
#include "scanner.h"

void slice_secret(int secret, int num_slices, int least_num_people) {
    int polunomial_degree = least_num_people - 1;
    int *coefficients;
    int *slices;
    int i, j, f_x;
    time_t t = time(NULL);
    struct tm date = *localtime(&t);

    printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Generating shares for key '%d'\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, secret);

    coefficients = malloc(sizeof(int)*polunomial_degree);
    slices = malloc(sizeof(int)*num_slices);
    if (coefficients == NULL || slices == NULL)
    {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    srand(time(0));
    for (i = 0; i < polunomial_degree; i++)
    {
        coefficients[i] = (rand() % 100) + 1;
        printf("%d, ",coefficients[i]);
    }
    
    for (i = 1; i <= num_slices; i++)
    {
        f_x = 0;
        for (j = 1; j <= polunomial_degree; j++)
        {
            f_x += coefficients[j-1]*pow(i, j);
        }
        f_x += secret;

        printf("(%d, %d)\n", i, f_x);
    }
    
    free(coefficients);
    free(slices);
}

int determinantOfMatrix(int mat[3][3]) {
    int ans;
    ans = mat[0][0] * (mat[1][1] * mat[2][2] - mat[2][1] * mat[1][2])
          - mat[0][1] * (mat[1][0] * mat[2][2] - mat[1][2] * mat[2][0])
          + mat[0][2] * (mat[1][0] * mat[2][1] - mat[1][1] * mat[2][0]);
    return ans;
}
 
// This function finds the solution of system of
// linear equations using cramer's rule
int findSolution(int **coeff) {
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    // Matrix d using coeff as given in cramer's rule
    int d[3][3] = {
        { coeff[0][0], coeff[0][1], coeff[0][2] },
        { coeff[1][0], coeff[1][1], coeff[1][2] },
        { coeff[2][0], coeff[2][1], coeff[2][2] },
    };
    // Matrix d1 using coeff as given in cramer's rule
    int d1[3][3] = {
        { coeff[0][3], coeff[0][1], coeff[0][2] },
        { coeff[1][3], coeff[1][1], coeff[1][2] },
        { coeff[2][3], coeff[2][1], coeff[2][2] },
    };
    // Matrix d2 using coeff as given in cramer's rule
    int d2[3][3] = {
        { coeff[0][0], coeff[0][3], coeff[0][2] },
        { coeff[1][0], coeff[1][3], coeff[1][2] },
        { coeff[2][0], coeff[2][3], coeff[2][2] },
    };
    // Matrix d3 using coeff as given in cramer's rule
    int d3[3][3] = {
        { coeff[0][0], coeff[0][1], coeff[0][3] },
        { coeff[1][0], coeff[1][1], coeff[1][3] },
        { coeff[2][0], coeff[2][1], coeff[2][3] },
    };
 
    // Calculating Determinant of Matrices d, d1, d2, d3
    double D = determinantOfMatrix(d);
    double D1 = determinantOfMatrix(d1);
    double D2 = determinantOfMatrix(d2);
    double D3 = determinantOfMatrix(d3);
 
    // Case 1
    if (D != 0) {
        // Coeff have a unique solution. Apply Cramer's Rule
        int x = D1 / D;
        int y = D2 / D;
        int z = D3 / D; // calculating z using cramer's rule
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Computed that a=%d and b=%d\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, x, y);
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Encryption key is: \033[0;34m%d\033[0m\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, z);
        return 1;
    }
    // Case 2
    /*else {
        if (D1 == 0 && D2 == 0 && D3 == 0)
            printf("Infinite solutions\n");
        else if (D1 != 0 || D2 != 0 || D3 != 0)
            printf("No solutions\n");
    }*/
    return 0; //something went wrong
}