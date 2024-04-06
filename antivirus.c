#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h> 
#include "scanner.h"
#include "inspector.h"

static const char *MONTH_STRING[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

int main(int argc, char* argv[]) {
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    char **file_arr;
    char **str_array;
    char **paths_to_strings;
    int file_num = 0, i=0, str_num = 0;
    
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
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Scanning directory %s\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, argv[2]);
        file_num = scan_dir(argv[2], &file_arr); 
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Found %d files\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, file_num);
        
        /*Search all the files in the filepath*/
        infection_scan(file_arr, file_num);
        
        /*Free file array*/
        for (i = 0; i < file_num; i++)
        {
            free(file_arr[i]);
        }
        free(file_arr);
        
    } else if (!strcmp(argv[1], "inspect")) {
        file_arr = (char **) malloc(sizeof(char *)); /*Intialize file array with space for 1 file pointer*/
        if (file_arr == NULL)
        {
            status_update(1, "Memory Allocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
       
        /*Find all the files in the filepath*/
        status_update(0, "Application Started");
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Scanning directory %s\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, argv[2]);
        file_num = scan_dir(argv[2], &file_arr); 
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Found %d files\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, file_num);
        
        /*Search all the files in the filepath t find the regex*/
        str_array = (char **) malloc(sizeof(char *)); /*Intialize file array with space for 1 file pointer*/
        paths_to_strings = (char **) malloc(sizeof(char *));
        if (str_array == NULL || paths_to_strings == NULL)
        {
            status_update(1, "Memory Allocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }

        str_num = inspection_scan(file_arr, file_num, &str_array, &paths_to_strings);
        
        for (i = 0; i < str_num; i++)
        {
            printf("%s\n", paths_to_strings[i]);
            printf("%s\n", str_array[i]);
        }
        
        /*Free file and string array*/
        for (i = 0; i < file_num; i++)
        {
            free(file_arr[i]);
        }
        free(file_arr);

        for (i = 0; i < str_num; i++)
        {
            free(str_array[i]);
        }
        free(str_array);
        free(paths_to_strings);

       /*No need to free paths of strings because they contain the pointers from file_array
       we just need to free the paths_to_strings ptr*/
    } else if (!strcmp(argv[1], "monitor")) {

    } else {
        status_update(1, "UNDEFINED ACTION\033[0m Available actions are: \033[0;36mscan inspect monitor\033[0m");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    return 0;
}