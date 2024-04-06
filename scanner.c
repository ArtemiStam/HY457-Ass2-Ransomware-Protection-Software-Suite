#define _GNU_SOURCE // includes _BSD_SOURCE for dt_type in dirent struct that is returned from readdir().
#include "scanner.h"

static const char *MONTH_STRING[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
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
    int i = 0, infected_num = 0;
    char *sha256_hash;
    char *md5_hash;
    char *infected_file_update;
    char update_message[49];
    char **infected_array;
    char *infection_type[] = {":REPORTED_SHA256_HASH", ":REPORTED_MD5_HASH", ":REPORTED_BITCOIN", ":REPORTED_VIRUS"};
    const char *MD5_malicious_lib =    "\x85\x57\x8c\xd4\x40\x4c\x6d\x58\x6c\xd0\xae\x1b\x36\xc9\x8a\xca";
    const char *SHA256_malicious_lib = "\xd5\x6d\x67\xf2\xc4\x34\x11\xd9\x66\x52\x5b\x32\x50\xbf\xaa\x1a\x85\xdb\x34\xbf\x37\x14\x68\xdf\x1b\x6a\x98\x82\xfe\xe7\x88\x49";
    const char *bitcoin_wallet =       "bc1qa5wkgaew2dkv56kfvj49j0av5nml45x9ek9hz6";
    const char *virus_signature =      "\x98\x1d\x00\x00\xec\x33\xff\xff\xfb\x06\x00\x00\x00\x46\x0e\x10";
    //"981d0000ec33ffff06000000460e10";
    //const char SHA256_malicious_lib[] = "d56d67f2c43411d966525b3250bfaa1a85db34bf371468df1b6a9882fee78849";
    //printf("MALICIOUS SHA256: %s\n", SHA256_malicious_lib);
    //printf("MALICIOUS MD5: %s\n", MD5_malicious_lib);
    
    status_update(0, "Scanning...");
    infected_array = (char **) malloc(sizeof(char *));
    if (infected_array == NULL)
    {
        status_update(1, "Memory Allocation failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    for (i = 0; i < file_num; i++)
    {  
       //Step 1: Compute SHA256 and MD5 hashes for every file and compare them with the known malicious library
       sha256_hash = (char *)SHA256_file(file_array[i]); 
       md5_hash = (char *)MD5_file(file_array[i]); 
       
       //Step 2: Search for the signature of the known virus
        if (search_bytes(file_array[i], virus_signature))
        {
            infected_file_update = (char *) malloc(strlen(file_array[i]) + strlen(infection_type[3]) + 1);
            if (infected_file_update == NULL)
            {
                status_update(1, "Memory Allocation failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
            strcpy(infected_file_update, file_array[i]);
            strcat(infected_file_update, infection_type[3]);
            infected_array[infected_num++] = infected_file_update;
            infected_array = realloc(infected_array, sizeof(char *)*(infected_num+1)); //add additional space in the array for 1 char pointer
            if (infected_array == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
        }
        
       //Step 3: Search for the reported Bitcoin address
       if (search_bytes(file_array[i], bitcoin_wallet))
        {
            infected_file_update = (char *) malloc(strlen(file_array[i]) + strlen(infection_type[2]) + 1);
            if (infected_file_update == NULL)
            {
                status_update(1, "Memory Allocation failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
            strcpy(infected_file_update, file_array[i]);
            strcat(infected_file_update, infection_type[2]);
            infected_array[infected_num++] = infected_file_update;
            infected_array = realloc(infected_array, sizeof(char *)*(infected_num+1)); //add additional space in the array for 1 char pointer
            if (infected_array == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
        }

       if (!strcmp(sha256_hash, SHA256_malicious_lib))
       {
            infected_file_update = (char *) malloc(strlen(file_array[i]) + strlen(infection_type[0]) + 1);
            if (infected_file_update == NULL)
            {
                status_update(1, "Memory Allocation failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
            strcpy(infected_file_update, file_array[i]);
            strcat(infected_file_update, infection_type[0]);
            infected_array[infected_num++] = infected_file_update;
            infected_array = realloc(infected_array, sizeof(char *)*(infected_num+1)); //add additional space in the array for 1 char pointer
            if (infected_array == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            //printf("File %s is infected\n", file_array[i]);
            
        } else if (!strcmp(md5_hash, MD5_malicious_lib)) {
            infected_file_update = (char *) malloc(strlen(file_array[i]) + strlen(infection_type[1]) + 1);
            if (infected_file_update == NULL)
            {
                status_update(1, "Memory Allocation failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
            strcpy(infected_file_update, file_array[i]);
            strcat(infected_file_update, infection_type[1]);
            infected_array[infected_num++] = infected_file_update;
            infected_array = realloc(infected_array, sizeof(char *)*(infected_num+1)); //add additional space in the array for 1 char pointer
            if (infected_array == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
        }
        
       free(sha256_hash);
       free(md5_hash);
    }

    status_update(0, "Operation finished");
    sprintf(update_message, "Processed %d files. \033[0;31mFound %d infected\033[0m", file_num, infected_num);
    status_update(0, update_message);

    for (i = 0; i < infected_num; i++)
    {
        printf("%s\n", infected_array[i]);
    }

    for (i = 0; i < infected_num; i++) //Free the array with the infected files
    {
        free(infected_array[i]);
    }
    free(infected_array);
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
    FILE* fp;
    unsigned char *hash;
    unsigned char *buffer;
    //unsigned int md_len;
    unsigned char *ptr;
    //EVP_MD_CTX *c;
    //const EVP_MD *EVP_md5();
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

    hash = (unsigned char*) malloc(MD5_DIGEST_LENGTH+1); //here it was EVP_MAX_MD_SIZE+1
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

    /*c = EVP_MD_CTX_new();
    EVP_DigestInit_ex(c, EVP_md5(), NULL);
    EVP_DigestUpdate(c, buffer, bytes_in_file);
    EVP_DigestFinal_ex(c, hash, &md_len);*/
    
    //MD5_Init(&c);
    //MD5_Update(&c, buffer, bytes_in_file);
    //MD5_Final(hash, &c);

    ptr = MD5(buffer, bytes_in_file, hash);
    if (ptr != hash)
    {
        status_update(1, "MD5 hashing failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    hash[MD5_DIGEST_LENGTH] = '\0'; //here it was EVP_MAX_MD_SIZE
    
    free(buffer);
    return hash;
}

int search_bytes(const char *file, const char *bytes) {
    FILE *fp;
    char *buffer;
    int i = 0, bytes_in_file = 0, bytes_read = 0, index = 0;

    if (file == NULL) {
        status_update(1, "Invalid file");
        status_update(1, "Application Ended");
        exit(1);
    }

    if (bytes == NULL)
    {
        status_update(1, "Invalid byte string");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    fp = fopen(file, "rb"); // Open the file in binary mode
    if (fp == NULL) {
        status_update(1, "File opening failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    fseek(fp, 0, SEEK_END);          // Jump to the end of the file
    bytes_in_file = ftell(fp);             // Get the current byte offset in the file
    rewind(fp);                      // Jump back to the beginning of the file

    buffer = (char *) malloc(bytes_in_file); // Enough memory for the file
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

    index = 0;
    for (i = 0; i < bytes_in_file; i++)
    {
        if (buffer[i] == bytes[index])
        {
            index++;
        } else {
            if (index == strlen(bytes))
            {
                break;
            }
            
            index = 0;
        }
    }
    
    free(buffer);
    if (index == strlen(bytes))
    {
        return 1;
    }
    return 0;
}
