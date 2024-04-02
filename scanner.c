#define _GNU_SOURCE // includes _BSD_SOURCE for dt_type in dirent struct that is returned from readdir().
#include "scanner.h"

/* String to print the name of the month*/
//static const char *MONTH_STRING[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

/*
This function prints a status update about the state of the antivitus.
Input: 
    int type: is the type of update, can be 0 = "INFO" or 1 = "ERROR"
    char *message: is the message to be printed with the update
Output: there is no return value.
*/
void status_update(int type,  char *message) {
    time_t t = time(NULL);
    struct tm date = *localtime(&t);

    if (type == 1)
    {
        fprintf(stderr, "\033[0;31m[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] %s\033[0m\n", "ERROR", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, message);
    }
    else if (type == 0)
    {
        printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] %s\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, message);
    }
}

char *construct_file_path(const char *directory,const char *addition){
    char *path;
    char *new_path;

    if (directory == NULL || addition == NULL)
    {
        status_update(1, "Directory is NULL");
        status_update(1, "Application Ended");
        exit(1);
    }

    path = (char *) malloc(strlen(directory)+1);
    if (path == NULL)
    {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    strcpy(path, directory);

    
    if (path[strlen(path)-1] == '/') //compare the last char of the string
    {
        new_path = (char *)realloc(path, strlen(path) + strlen(addition) + 1);
        if (new_path == NULL)
        {
            status_update(1, "Memory Reallocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
        strcat(new_path, addition);
    } else {

        new_path = (char *)realloc(path, strlen(path) + strlen(addition) + 2);
        if (new_path == NULL)
        {
            status_update(1, "Memory Reallocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
        
        strcat(new_path, "/");
        strcat(new_path, addition);
    }
    return new_path;
}

char **scan_dir(const char *directory, char **file_arr) {
    DIR *dir = opendir(directory); /*Open directory and get pointer to directory stream*/
    struct dirent *file;
    char *file_path;
    char *dir_path;
    //char **ptr;
    //char **new_ptr;
    static int file_num = 0;

    if (dir == NULL || directory == NULL) /*opendir return NULL on error*/
    {
        status_update(1, "Directory opening failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    /*ptr = (char **) malloc(sizeof(char *));
    if (ptr == NULL)
    {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }*/
    //file = readdir(dir); /*get a pointer to the dirent structure of the next directory entry*/
    while ((file = readdir(dir)) != NULL) /*While we have not reached the end of the directory tree*/
    {
        if (file->d_type == DT_DIR) {

            if (strcmp(file->d_name, ".") && strcmp(file->d_name, "..")) {
                dir_path = construct_file_path(directory, file->d_name);

                file_arr = scan_dir(dir_path, file_arr);
                //file_arr = ptr;
                //free(dir_path);
            }

        } else if (file->d_type == DT_REG) {
           
            file_path = construct_file_path(directory, file->d_name);
            file_arr[file_num++] = file_path;

            file_arr = (char **)realloc(file_arr, sizeof(char *)*file_num+1); /*add additional space in the array for 1 char pointer*/
            if (file_arr == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
        }
    }
    
    return file_arr;
}