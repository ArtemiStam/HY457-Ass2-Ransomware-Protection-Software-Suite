#define _GNU_SOURCE // includes _BSD_SOURCE for dt_type in dirent struct that is returned from readdir().
#include "scanner.h"

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
    char *new_path;

    if (directory == NULL || addition == NULL)
    {
        status_update(1, "Directory is NULL");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    if (directory[strlen(directory)-1] == '/') //compare the last char of the string
    {
        new_path = (char *)malloc(strlen(directory) + strlen(addition) + 1);
        if (new_path == NULL)
        {
            status_update(1, "Memory Reallocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
        strcpy(new_path, directory);
        strcat(new_path, addition);
    } else {

        new_path = (char *) malloc(strlen(directory) + strlen(addition) + 2);
        if (new_path == NULL)
        {
            status_update(1, "Memory Reallocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
        
        strcpy(new_path, directory);
        strcat(new_path, "/");
        strcat(new_path, addition);
    }
    return new_path;
}

int scan_dir(const char *directory, char ***file_arr) {
    DIR *dir;
    struct dirent *file;
    char *file_path;
    char *dir_path;
    //char **ptr;
    //char **new_ptr;
    static int file_num = 0;

    dir = opendir(directory); /*Open directory and get pointer to directory stream*/
    if (dir == NULL || directory == NULL) /*opendir return NULL on error*/
    {
        status_update(1, "Directory opening failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    while ((file = readdir(dir)) != NULL) /*While we have not reached the end of the directory tree*/
    {
        if (file->d_type == DT_DIR) {

            if (strcmp(file->d_name, ".") && strcmp(file->d_name, "..")) {
                dir_path = construct_file_path(directory, file->d_name);

                scan_dir(dir_path, file_arr);
                free(dir_path);
            }

        } else if (file->d_type == DT_REG) {
           
            file_path = construct_file_path(directory, file->d_name);
            (*file_arr)[file_num++] = file_path;

            *file_arr = (char **)realloc(*file_arr, sizeof(char *)*(file_num+1)); /*add additional space in the array for 1 char pointer*/
            if (*file_arr == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
        }
    }
    
    closedir(dir);
    return file_num;
}

void infection_scan(char** file_array, int file_num) {
    int i = 0;
    char *sha256_hash;
    char *md5_hash;
    const char *MD5_malicious_lib =    "\x85\x57\x8c\xd4\x40\x4c\x6d\x58\x6c\xd0\xae\x1b\x36\xc9\x8a\xca";
    const char *SHA256_malicious_lib = "\xd5\x6d\x67\xf2\xc4\x34\x11\xd9\x66\x52\x5b\x32\x50\xbf\xaa\x1a\x85\xdb\x34\xbf\x37\x14\x68\xdf\x1b\x6a\x98\x82\xfe\xe7\x88\x49";
    //const char SHA256_malicious_lib[] = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
    printf("MALICIOUS SHA256: %s\n", SHA256_malicious_lib);
    printf("MALICIOUS MD5: %s\n", MD5_malicious_lib);
    
    for (i = 0; i < file_num; i++)
    {
       /*Step 1: Compute SHA256 and MD5 hashes for every file and compare them with the known malicious library*/
       sha256_hash = (char *)SHA256_file(file_array[i]); 
       md5_hash = (char *)MD5_file(file_array[i]); 
       printf("SHA256: %s\n", sha256_hash);
       if (!strcmp(sha256_hash, SHA256_malicious_lib))
       {
            printf("File %s is infected\n", file_array[i]);
       }
       
       free(sha256_hash);
    }
}

unsigned char *SHA256_file(const char *file){
    FILE* fp;
    unsigned char *hash;
    unsigned char *buffer;
    unsigned char *ptr;
    long bytes_in_file, bytes_read;

    if (file == NULL) {
        status_update(1, "Invalid file");
        status_update(1, "Application Ended");
        exit(1);
    }

    fp = fopen(file, "rb"); // Open the file in binary mode
    if (fp == NULL) {
        status_update(1, "File opening failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    hash = (unsigned char*) malloc(SHA256_DIGEST_LENGTH+1);
    if (hash == NULL)
    {
        status_update(1, "Memory Allocation failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    fseek(fp, 0, SEEK_END);          // Jump to the end of the file
    bytes_in_file = ftell(fp);             // Get the current byte offset in the file
    rewind(fp);                      // Jump back to the beginning of the file

    buffer = (unsigned char *) malloc(bytes_in_file); // Enough memory for the file
    if (buffer == NULL)
    {
        status_update(1, "Memory Allocation failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    bytes_read = fread(buffer, 1, bytes_in_file, fp); // Read in the entire file
    if (bytes_read != bytes_in_file)
    {
        status_update(1, "File Reading failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    fclose(fp);

    ptr = SHA256(buffer, bytes_in_file, hash);
    if (ptr != hash)
    {
        status_update(1, "SHA256 hashing failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    hash[SHA256_DIGEST_LENGTH] = '\0';
    
    free(buffer);
    return hash;
}

unsigned char *MD5_file(const char *file) {

}