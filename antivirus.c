#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "scanner.h"
#include "inspector.h"
#include "monitor.h"
#include "secret_sharing.h"

int main(int argc, char *argv[])
{
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    char **file_arr;       /*contains file paths*/
    char **str_array;      /*contains the strings found in all the files*/
    char **addresses;      /*contains the addresses(domains) found by using a regex on the strings*/
    int *paths_to_strings; /*contains indexes to paths in file_array for each extracted string*/
    int *paths;            /*contains indexes to the paths in file_array for each address that is extracted from a string*/
    int file_num = 0, i = 0, j = 0, secret, count = 0;
    long val;
    char *p;
    int **coeff;
    int **temp;
    int int_array[4];

    if (argc < 3)
    {
        status_update(1, "UNSUPPORTED NUMBER OF ARGUMENTS");
        status_update(1, "Application Ended");
        exit(1);
    }

    if (!strcmp(argv[1], "scan"))
    {
        file_arr = (char **)malloc(sizeof(char *)); /*Intialize file array with space for 1 file pointer*/
        if (file_arr == NULL)
        {
            status_update(1, "Memory Allocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }

        /*Find all the files in the filepath*/
        status_update(0, "Application Started");
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Scanning directory %s\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, argv[2]);
        file_num = scan_dir(argv[2], &file_arr);
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Found %d files\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, file_num);

        /*Search all the files in the filepath*/
        infection_scan(file_arr, file_num);

        /*Free file array*/
        for (i = 0; i < file_num; i++)
        {
            free(file_arr[i]);
        }
        free(file_arr);
    }
    else if (!strcmp(argv[1], "inspect"))
    {
        file_arr = (char **)malloc(sizeof(char *)); /*Intialize file array with space for 1 file pointer*/
        if (file_arr == NULL)
        {
            status_update(1, "Memory Allocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }

        /*Find all the files in the filepath*/
        status_update(0, "Application Started");
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Scanning directory %s\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, argv[2]);
        file_num = scan_dir(argv[2], &file_arr);
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Found %d files\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, file_num);

        str_array = (char **)malloc(sizeof(char *));   /*Intialize str_array with space for 1 pointer(char *) to a file path*/
        paths_to_strings = (int *)malloc(sizeof(int)); /*Intialize paths_to_strings with space for 1 integer*/
        addresses = (char **)malloc(sizeof(char *));   /*Initialize addresses with space for 1 pointer(char *) to an address/domain*/
        paths = (int *)malloc(sizeof(int));            /*Initialize paths with space for 1 integer*/
        if (str_array == NULL || paths_to_strings == NULL || addresses == NULL || paths == NULL)
        {
            status_update(1, "Memory Allocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }

        /*Inspect files for malicious domains*/
        inspection_scan(file_arr, file_num, &str_array, &paths_to_strings, &addresses, &paths);

        for (i = 0; i < file_num; i++)
        {
            free(file_arr[i]);
        }
        free(file_arr);
    }
    else if (!strcmp(argv[1], "monitor"))
    {
        status_update(0, "Application Started");
        event_listener(argv[2]); /*Start listening to events*/
    }
    else if (!strcmp(argv[1], "slice"))
    {
        status_update(0, "Application Started");
        
        if (atoi(argv[2]) <= 0) //input is not numeric
        {
            status_update(1, "Input must be numeric");
            status_update(1, "Application Ended");
            exit(1);
        }
        secret = atoi(argv[2]);
        
        slice_secret(secret, 10, 3); /* Create 10 shares of the secret so that at least 3 people can access the secret*/
    }
    else if (!strcmp(argv[1], "unlock"))
    {
        if (argc < 5)
        {
            status_update(1, "Need at least 3 different shares");
            status_update(1, "Application Ended");
            exit(1);
        }
        status_update(0, "Application Started");
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Received %d different shares\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year + 1900, date.tm_hour, date.tm_min, date.tm_sec, argc - 2);

        coeff = malloc(sizeof(int*)*(argc-2));
        if (coeff == NULL)
        {
            exit(1);
        }

        for (i = 2; i < argc; i++)
        {
            count = 0; // for error checking
            p = argv[i];
            while (*p) // While there are more characters to process
            {   
                if (isdigit(*p) || ((*p == '-' || *p == '+') && isdigit(*(p + 1)))) //if we find a digit or +,- and a digit after
                {
                    // Found a number
                    val = strtol(p, &p, 10); // Read number
                    count++;
                    if (count == 1 && *p != ',') // after the first number we always want a comma ','
                    {
                        status_update(1, "Input must be: x,y");
                        status_update(1, "Application Ended");
                        exit(1);
                    }

                    /*Create array [val^2, val, 1, val2(second val)] it translates to f(val) = a*(val^2) + b*val + 1*c = val2*/
                    if (count == 1) //first number
                    {
                        int_array[0] = pow(val,2);
                        int_array[1] = val;
                        int_array[2] = 1;
                    } else if (count == 2){ //second number
                        int_array[3] = val;
                    }
                }
                else
                {                    
                    p++; // Otherwise, move on to the next character.
                }
            }

            if (count != 2) // need 2 numbers for each share
            {
                status_update(1, "Input must be: x,y");
                status_update(1, "Application Ended");
                exit(1);
            }

            coeff[i-2] = malloc(sizeof(int)*4); // malloc space for an array of 4 ints 
            if (coeff[i-2] == NULL)
            {
                exit(1);
            }
            for (j = 0; j < 4; j++)
            {
                coeff[i-2][j] = int_array[j];
            }
        }

        /*for ( i = 0; i < argc-2; i++) //print 2d array
        {
            printf("[%d, %d, %d, %d]\n", coeff[i][0], coeff[i][1], coeff[i][2], coeff[i][3]);
        }*/
        
        temp = coeff;
        i = 0;
        /*if the system cant be solved with the first three shares try the next three if there are any*/
        while(!solve_system(temp) && i < argc-2) {
            i++;
            temp = &temp[i];
            if (argc - 2 == 3 || argc - i < 3)
            {
                status_update(1, "Incorrect input values, no solution found");
                status_update(1, "Application Ended");
                exit(1);
            }
        }
        
        for (i = 0; i < argc-2; i++) //free array of coefficients
        {
            free(coeff[i]);
        }
        free(coeff);
    }
    else
    {
        status_update(1, "UNDEFINED ACTION\033[0m Available actions are: \033[0;36mscan inspect monitor\033[0m");
        status_update(1, "Application Ended");
        exit(1);
    }

    return 0;
}