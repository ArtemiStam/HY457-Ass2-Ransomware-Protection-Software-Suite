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

/*----------------------Utils------------------------*/
static const char *MONTH_STRING[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}; /* String to print the name of the month */
void status_update(int type,  char *message); 

/*---------------------------------------------------*/
char *construct_file_path(const char *directory, const char *addition);
int scan_dir(const char *directory, char ***file_arr);
void infection_scan(char** file_array, int file_num);
int search_bytes(const char *file, const char *bytes, int num_bytes);

/*-----------------Hashing----------------------------*/
unsigned char *SHA256_file(const char *file);
unsigned char *MD5_file(const char *file);


#endif