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
    /*size_t realsize = size * nmemb;
    char **response = (char **)userdata;
    *response = (char *)malloc(realsize + 1);
    memcpy(*response, (char *)data, realsize);
    return realsize;*/
    size_t realsize = size * nmemb;
    struct Memory *mem = (struct Memory *)userdata;

    char *ptr = realloc(mem->data, mem->size + realsize + 1);
    if (!ptr) {
        printf("not enough memory (realloc returned NULL)\n");
        return 0; /* out of memory! */
    }
    mem->data = ptr;
    memcpy(&(mem->data[mem->size]), data, realsize);
    mem->size += realsize;
    mem->data[mem->size] = '\0';

    return realsize;
}

int inspection_scan(char **file_array, const int file_num, char ***str_array, int **paths_to_strings, char ***addresses, int **paths)
{
    int i = 0, j = 0, total_strs = 0, str_num = 0, addr_num = 0;
    int *malicious_addr;

    if (file_array == NULL || str_array == NULL || paths_to_strings == NULL || addresses == NULL || paths == NULL)
    {
        status_update(1, "Invalid file");
        status_update(1, "Application Ended");
        exit(1);
    }

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
                (*paths_to_strings)[j] = i;
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
    /*Using CURLlib to do a GET request*/
    for (i = 0; i < addr_num; i++)
    {
        malicious_addr[i] = check_malicious((*addresses)[i]);
    }

    for (i = 0; i < addr_num; i++)
    {
        //printf("%s\n", file_array[(*paths)[i]]);
        printf("%s\n", (*addresses)[i]);
        printf("Malicious: %d\n", malicious_addr[i]);
    }

    for (i = 0; i < addr_num; i++)
    {
        free((*addresses)[i]);
    }
    free(*addresses);
    free(*paths);
    return total_strs;
    /*After we get the strings we need to use regexto get domains*/
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
            if (str_len == 0)
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
            string = (char *)realloc(string, str_len + 1);
            if (string == NULL)
            {
                status_update(1, "Memory Reallocation Failed");
                status_update(1, "Application Ended");
                exit(1);
            }

            if ((printable_chars == bytes_in_file) && (str_len >= 4))
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
            if (str_len >= 4)
            {
                str_num++;
                string[str_len] = '\0';
                (*str_array)[total_strs++] = string;
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

            str_len = 0;
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

    strcpy(re, "((www.))?[-a-zA-Z0-9.]+\\.(net|com|gr|org){1}[-a-zA-Z0-9./]*");

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

    for (i = 0; i < str_num; i++)
    {
        buf = str_array[i];
        s = buf;
        while (1)
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

            // offset = pmatch[0].rm_so + (s - buf);
            // printf("address = %s\n",s + pmatch[0].rm_so);
            length = pmatch[0].rm_eo - pmatch[0].rm_so;
            if (!check_duplicates(*addresses, s + pmatch[0].rm_so, addr_num, length))
            {
                (*paths)[addr_num] = paths_to_strings[i];
                (*addresses)[addr_num] = malloc(length + 1);
                (*addresses)[addr_num][length] = '\0';
                memcpy((*addresses)[addr_num++], s + pmatch[0].rm_so, length);
                *paths = realloc(*paths, sizeof(int) * (addr_num + 1));
                *addresses = realloc(*addresses, sizeof(char *) * (addr_num + 1));
                if (*addresses == NULL || *paths == NULL)
                {
                    status_update(1, "Memory Reallocation Failed");
                    status_update(1, "Application Ended");
                    exit(1);
                }
                // s += pmatch[0].rm_eo;
            }
            s += pmatch[0].rm_eo;
            // s += pmatch[0].rm_eo;
            // printf("offset = %jd; length = %jd\n", (intmax_t)offset, (intmax_t)length);
            // printf("address = \"%.*s\"\n", length, s + pmatch[0].rm_so);
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
    
    url = malloc(strlen(str) + strlen(address) + 1);
    response.data = malloc(1);
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
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);
    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(rc));
    }
    
    if (strstr(response.data,  "\"Comment\":[\"EDE(16): Censored\"]") != NULL) {
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