#include "scanner.h"
#include "inspector.h"

#include <assert.h>

#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof((arr)[0]))

struct Memory {
  char *data;
  size_t size;
};


size_t write_callback(char *data, size_t size, size_t nmemb, void *userdata)
{
    size_t realsize = size * nmemb;
    struct Memory *mem = (struct Memory *)userdata; //since function signature has void * for the insput data we need to assign it to a struct Memory type variable to manipulate it

    char *ptr = realloc(mem->data, mem->size + realsize + 1); // allocate size for the input data
    if (!ptr) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0; /* out of memory! */
    }
    mem->data = ptr; 
    memcpy(&(mem->data[mem->size]), data, realsize); // copy data in allocated memory
    mem->size += realsize; 
    mem->data[mem->size] = '\0'; // data is not null terminated so we make it to use it as a string

    return realsize;
}

int inspection_scan(char **file_array, const int file_num, char ***str_array, int **paths_to_strings, char ***addresses, int **paths)
{
    int i = 0, j = 0, total_strs = 0, str_num = 0, addr_num = 0;
    int *malicious_addr;
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    char *file_name;
    char *string;
    int  length = 0;

    if (file_array == NULL || str_array == NULL || paths_to_strings == NULL || addresses == NULL || paths == NULL)
    {
        status_update(1, "Invalid file");
        status_update(1, "Application Ended");
        exit(1);
    }

    status_update(0, "Searching...");
    for (i = 0; i < file_num; i++) /*Get the strings from every file*/
    {
        if ((str_num = extract_strings(file_array[i], str_array, total_strs)) > 0) /*add strings to str_array*/
        {
            total_strs = total_strs + str_num;
            *paths_to_strings = realloc(*paths_to_strings, sizeof(int) * (total_strs + 1)); 
            if (*paths_to_strings == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }

            for (j = total_strs - str_num; j < total_strs; j++)
            {
                (*paths_to_strings)[j] = i;  // add to path_to_strings an index that represents this files path to every string extracted from the file   
            }
        }
    }

    /*Check if string contains address and fill paths buffer with the index to the file path*/
    addr_num = extract_addresses(*str_array, addresses, total_strs, *paths_to_strings, paths);

    /*free here because we no longer need it and we want to have space in the heap*/
    for (i = 0; i < total_strs; i++)
    {
        free((*str_array)[i]);
    }
    free(*str_array);
    free(*paths_to_strings); 
    
    malicious_addr = malloc(sizeof(int) * addr_num);
    for (i = 0; i < addr_num; i++)
    {
        malicious_addr[i] = check_malicious((*addresses)[i]); /*Check if extracted domains/addresses are malicious*/
    }
    status_update(0, "Operation finished");
    printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Processed %d files.\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, file_num);

    /*Print output*/
    printf("\n| %-20s | %-80s | %-50s| %-11s |\n", "FILE", "PATH", "DOMAIN", "RESULT");
    printf("=============================================================================================================================================================================\n");
    for (i = 0; i < addr_num; i++)
    {
        length = strlen(file_array[(*paths)[i]]);   
        string = malloc(length+1);

        strcpy(string, file_array[(*paths)[i]]);
        if (string[length-1] == '/')
        {
            string[length-1] = '\0';
        }
        file_name = strrchr(string, '/');
        if (file_name == NULL)
        {
            status_update(1, "strrchr Function Failed");
            status_update(1, "Application Ended");
            exit(1);
        }
        file_name[0] = '\0';
        printf("| %-20s | %-80s | %-50s| %-22s |\n", file_name+1, string, (*addresses)[i], malicious_addr[i] ? "\033[0;31mMalicious\033[0m " : "\033[0;32mSafe\033[0m");
        free(string);
    }

    for (i = 0; i < addr_num; i++)
    {
        free((*addresses)[i]);
    }
    free(*addresses);
    free(*paths);
    //free(*paths_to_strings);
    free(malicious_addr);
    return total_strs;
}

int extract_strings(const char *file, char ***str_array, int total_strs)
{
    FILE *fp;
    char *buffer;
    char *string;
    int i = 0, bytes_in_file = 0, bytes_read = 0;
    int str_len = 0, printable_chars = 0, str_num = 0;

    if (file == NULL)
    {
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
    if (fp == NULL)
    {
        status_update(1, "File opening failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    fseek(fp, 0, SEEK_END);    // Jump to the end of the file
    bytes_in_file = ftell(fp); // Get the current byte offset in the file
    rewind(fp);                // Jump back to the beginning of the file

    buffer = (char *)malloc(bytes_in_file + 1); // Enough memory for the file
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

    for (i = 0; i < bytes_in_file; i++)
    {
        if ((buffer[i] <= 126) && (buffer[i] >= 32))
        {
            printable_chars++;
            if (str_len == 0) // when first printable char is encountered, malloc space for it 
            {
                string = (char *)malloc(1);
                if (string == NULL)
                {
                    status_update(1, "Memory Allocation failed");
                    status_update(1, "Application Ended");
                    exit(1);
                }
            }

            string[str_len++] = buffer[i]; 
            string = (char *)realloc(string, str_len + 1); // allocate space for the next printable char
            if (string == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }

            if ((printable_chars == bytes_in_file) && (str_len >= 4)) // if this is the last byte of the file and the string collected so far has 4 or more chars add it to the string array
            {
                str_num++;
                string[str_len] = '\0';
                (*str_array)[total_strs++] = string;
                *str_array = (char **)realloc(*str_array, sizeof(char *)*(total_strs + 1));
                if (*str_array == NULL)
                {
                    status_update(1, "Memory Reallocation Failed");
                    status_update(1, "Application Ended");
                    exit(1);
                }
            }
        }
        else
        {
            if (str_len >= 4) // if the collected string is 4 or more chars
            {
                str_num++;
                string[str_len] = '\0';
                (*str_array)[total_strs++] = string; //add it to string array
                *str_array = (char **)realloc(*str_array, sizeof(char *) * (total_strs + 1));  
                if (*str_array == NULL)
                {
                    status_update(1, "Memory Reallocation Failed");
                    status_update(1, "Application Ended");
                    exit(1);
                }
            }
            if (str_len < 4 && str_len > 0) 
            {
                free(string);
            }

            str_len = 0; // reset the length coutner to zero for the next string
        }
    }

    if (str_len < 4 && str_len > 0)
    {
        free(string);
    }

    free(buffer);
    return str_num;
    /*να κάνω free τον buffer απο την συναρτηση που την καλει*/
}

int extract_addresses(char **str_array, char ***addresses, int str_num, int *paths_to_strings, int **paths)
{
    regex_t regex;
    regmatch_t pmatch[1]; // Up to 3 sub-expressions
    regoff_t length;
    int ret, i, addr_num = 0;
    char re[1000];
    // char *string;
    char *s;
    char *buf = NULL;

    strcpy(re, "((www.))?[-a-zA-Z0-9]+\\.(net|com|gr|org)"); //set the regex we want to extract the addresses, last regex: "((www.))?[-a-zA-Z0-9.]+\\.(net|com|gr|org){1}[-a-zA-Z0-9./]*"

    if (str_array == NULL || addresses == NULL || paths_to_strings == NULL || paths == NULL)
    {
        status_update(1, "Invalid Pointer");
        status_update(1, "Application Ended");
        exit(1);
    }

    // Extended Regular Expressions, case insensitive search
    if ((ret = regcomp(&regex, re, REG_EXTENDED)) == 1)
    {
        regerror(ret, &regex, buf, sizeof(buf));
        fprintf(stderr, "Error: regcomp: %s\n", buf);
        status_update(1, "Regex could not compile");
        status_update(1, "Application Ended");
        exit(1);
    }

    for (i = 0; i < str_num; i++) //for every string in the string array
    {
        buf = str_array[i];
        s = buf;
        while (1) //while regex doesnt return REG_NOMATCH
        {
            if ((ret = regexec(&regex, s, ARRAY_SIZE(pmatch), pmatch, 0)) == 1)
            {
                if (ret != REG_NOMATCH)
                {
                    (void)regerror(ret, &regex, buf, sizeof(buf));
                    fprintf(stderr, "Error: regexec: %s\n", buf);
                    exit(EXIT_FAILURE);
                }
                break;
            }

            length = pmatch[0].rm_eo - pmatch[0].rm_so; //find length of extract
            (*paths)[addr_num] = paths_to_strings[i]; //save the path to the file that the address/domain has beeen extracted from
            (*addresses)[addr_num] = malloc(length + 1);
            (*addresses)[addr_num][length] = '\0';
            memcpy((*addresses)[addr_num++], s + pmatch[0].rm_so, length); //copy the extracted address/domain to the addresses array
            *paths = realloc(*paths, sizeof(int) * (addr_num + 1)); //realloc an extra space for the next path
            *addresses = realloc(*addresses, sizeof(char *) * (addr_num + 1)); //realloc an extra space for the next *address
            if (*addresses == NULL || *paths == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }

            s += pmatch[0].rm_eo;
        }
    }

    // free internal storage fields associated with regex
    regfree(&regex);

    return addr_num;
}

int check_duplicates(char **addresses, char *address, int addr_num, int length)
{
    int i = 0;
    for (i = 0; i < addr_num; i++)
    {
        if (!strncmp(address, addresses[i], length))
        {
            return 1;
        }
    }
    return 0;
}

int check_malicious(char *address){
    CURL *curl;
    CURLcode rc;
    struct curl_slist *list = NULL;
    char *url; 
    struct Memory response;
    char *str = "https://family.cloudflare-dns.com/dns-query?name="; 
    
    if (address == NULL) {
        status_update(1, "Invalid Pointer");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    url = malloc(strlen(str) + strlen(address) + 1); // allcoate string for the url we want to send a request to
    response.data = malloc(1); // allocate space for the data we are going to receive
    response.size = 0;
    if (url == NULL || response.data == NULL) {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    strcpy(url,str); 
    strcat(url, address);
    curl = curl_easy_init();
    if (!curl) {
        status_update(1, "Curl Library Failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    list = curl_slist_append(list, "accept: application/dns-json");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list); // add header in list to the headers of the packet to be sent
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback); // set function to be called when response comes
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response); // set input data for write_callback
    rc = curl_easy_perform(curl); //perform request
    if (rc != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rc));
    }
    
    if (strstr(response.data,  "\"Comment\":[\"EDE(16): Censored\"]") != NULL) { // search response for malicious indicator
        curl_slist_free_all(list); 
        curl_easy_cleanup(curl);
        free(url);
        free(response.data);
        return 1;
    } 
    
    curl_slist_free_all(list); 
    curl_easy_cleanup(curl);
    free(url);
    free(response.data);
    
    return 0;
}