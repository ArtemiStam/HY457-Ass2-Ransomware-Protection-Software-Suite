#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h> 
#include "scanner.h"


int main(int argc, char* argv[]) {
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    char **file_arr;
    int file_num = 0, i=0;
    
    if (argc != 3)
    {
        status_update(1, "UNSUPPORTED NUMBER OF ARGUMENTS");
        status_update(1, "Application Ended");
        exit(1);
    }
    

    if (!strcmp(argv[1], "scan")) {

        file_arr = (char **) malloc(sizeof(char *)); /*Intialize file array with space for 1 file pointer*/
        if (file_arr == NULL)
        {
            status_update(1, "Memory Allocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }

        /*Find all the files in the filepath*/
        status_update(0, "Application Started");
        status_update(0, "Scanning Directory");
        file_arr = scan_dir(argv[2], file_arr); 
        //printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Found %d files\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, file_num);
        /*Search all the files in the filepath*/
        printf("%s %s\n", file_arr[0], file_arr[1]);
        
       
    } else if (!strcmp(argv[1], "inspect")) {

    } else if (!strcmp(argv[1], "monitor")) {

    } else {
        status_update(1, "UNDEFINED ACTION\033[0m Available actions are: \033[0;36mscan inspect monitor\033[0m");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    return 0;
}