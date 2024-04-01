#ifndef _SCANNER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md2.h>
#include <openssl/sha.h>
#include <time.h>
#include <unistd.h> /*Needed for function getppid()*/
#include <sys/types.h> /*Needed to recognise 'DIR' type*/
#include <dirent.h>    /*Needed for functions opendir(), readdir()*/

/* String to print the name of the month */
static const char *MONTH_STRING[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

void status_update(int type,  char *message); 
char *construct_file_path(const char *directory, const char *addition);
int scan_dir(const char *directory, char **file_arr);

#endif