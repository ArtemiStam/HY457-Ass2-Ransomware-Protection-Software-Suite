#include "scanner.h"
#include "inspector.h"

int inspection_scan(char **file_array, const int file_num, char ***str_array, char ***paths_to_strings) {
    int i = 0, j = 0, total_strs = 0, str_num = 0;

    if (file_array == NULL || str_array == NULL || paths_to_strings == NULL) {
        status_update(1, "Invalid file");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    for (i = 0; i < file_num; i++) /*Get the strings from every file*/
    {
        if ((str_num = extract_strings(file_array[i], str_array, total_strs)) > 0) /*add strings to str_array*/
        {
            total_strs = total_strs + str_num;
            *paths_to_strings = realloc(*paths_to_strings, sizeof(char *)*(total_strs+1));
            if (*paths_to_strings == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }
            
            for (j = total_strs - str_num; j < total_strs; j++)
            {
                (*paths_to_strings)[j] = file_array[i];
            }
        }
    }

    return total_strs;
    /*After we get the strings we need to use regexto get domains*/
}

int extract_strings(const char *file, char ***str_array, int total_strs) {
    FILE *fp;
    char *buffer;
    //char *string;
    int i = 0, bytes_in_file = 0, bytes_read = 0;
    int /*tail = 0,*/ printable_chars = 0, str_num = 0;

    if (file == NULL) {
        status_update(1, "Invalid file");
        status_update(1, "Application Ended");
        exit(1);
    }

    if (str_array == NULL)
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

    buffer = (char *) malloc(bytes_in_file+1); // Enough memory for the file
    if (buffer == NULL)
    {
        status_update(1, "Memory Allocation failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    buffer[bytes_in_file] = '\0';

    bytes_read = fread(buffer, 1, bytes_in_file, fp); // Read in the entire file
    if (bytes_read != bytes_in_file)
    {
        status_update(1, "File Reading failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    fclose(fp);

    //tail = 0;
    for (i = 0; i < bytes_in_file; i++)
    {
        if ((buffer[i] <= 126) && (buffer[i] >= 32))
        {
            /*if (i == 0)
            {
                tail = -1;
            }*/
        
            printable_chars++;
            /*if (i == bytes_in_file-1 && tail != -1)
            {
                if (i - tail >= 4) //for it to be a domain it must be at least 4 characters long a.gr
                {
                    str_num++;
                    string  = (char *) malloc(i - tail + 1);
                    if (string == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    memcpy(string, buffer + tail + 1, i - tail); //using pointer arithmetic to start copying from the desired index
                    string[i - tail + 1] = '\0';

                    *str_array = realloc(*str_array, ++total_strs);
                    if (*str_array == NULL)
                    {
                        status_update(1, "Memory Reallocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    (*str_array)[total_strs-1] = string;
                }
            }
            
        } else {
            if (tail == -1)
            {
                if (i >= 4) //for it to be a domain it must be at least 4 characters long a.gr
                {
                    str_num++;
                    string = (char *)malloc(i + 1);
                    if (string == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    memcpy(string, buffer, i);
                    string[i + 1] = '\0';
                     
                    *str_array = realloc(*str_array, ++total_strs); //Add to the str_array a place for an additional string
                    if (*str_array == NULL)
                    {
                        status_update(1, "Memory Reallocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    (*str_array)[total_strs-1] = string;
                }
            }
            else {
                if (i - tail - 1 >= 4) //for it to be a domain it must be at least 4 characters long a.gr
                {
                    str_num++;
                    string = malloc(i - tail);
                    if (string == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    memcpy(string, buffer + tail + 1, i - tail - 1); //using pointer arithmetic to start copying from the desired index
                    string[i - tail] = '\0';
                     
                    *str_array = realloc(*str_array, ++total_strs); //Add to the str_array a place for an additional string
                    if (*str_array == NULL)
                    {
                        status_update(1, "Memory Reallocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    (*str_array)[total_strs-1] = string;
                }
            }
            tail = i;*/
        } 
    } 

    if (printable_chars == bytes_in_file)
    {
        str_num++;
        (*str_array)[total_strs++] = buffer;
        *str_array = (char **)realloc(*str_array, sizeof(char *) *(total_strs+1));
        if (*str_array == NULL)
        {
            status_update(1, "Memory Reallocation Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
    } else {
        free(buffer);
    }
    
    return str_num;
    /*να κάνω free τον buffer απο την συναρτηση που την καλει*/
}