#ifndef _SCANNER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>         /*Needed to print time in output prompt*/
#include <unistd.h>       /*Needed for function getppid()*/
#include <sys/types.h>    /*Needed to recognise 'DIR' type*/
#include <dirent.h>       /*Needed for functions opendir(), readdir()*/
#include <openssl/sha.h>  /*Needed for SHA256 hashing*/
#include <openssl/md5.h>  /*Needed for MD5 hashing*/

/*----------------------Utils-------------------------------------------------------------------------------------------------------------------------------------------*/
static const char *MONTH_STRING[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}; /* String to print the name of the month */
/*
This function prints a status update about the state of the antivitus.
Input: 
    int type: is the type of update, can be 0 = "INFO" or 1 = "ERROR"
    char *message: is the message to be printed with the update
Output: there is no return value.
*/
void status_update(int type,  char *message); 


/*----------------------------------------------------------------------------------------------------------------------------------------------------------------------*/
/*Takes a path to a directory and addition information to append to the path*/
char *construct_file_path(const char *directory, const char *addition);
/* Scan reqursively the given directory and its subdirectories and return the path to all the files in file_arr*/
int scan_dir(const char *directory, char ***file_arr);
/* Scans the files in the file_array for virus signature, bitcoin wallet and malicious library hashes*/
void infection_scan(char** file_array, int file_num);
/*Takes the path to a file, the bytes string we want to search, the length of the byte string and returns if the file contains the bytes*/
int search_bytes(const char *file, const char *bytes, int num_bytes);


/*-----------------Hashing----------------------------------------------------------------------------------------------------------------------------------------------*/
/*Takes the path to a file and return the SHA256 hash of its content*/
unsigned char *SHA256_file(const char *file);
/*Takes the path to a file and return the MD5 hash of its content*/
unsigned char *MD5_file(const char *file);


#endif