#ifndef _INSPECTOR_H_
#include <regex.h>      /*Needed to filter domains from file contents*/
#include <curl/curl.h>  /*Needed to send requests to Cloudflare if domain is malicious*/

size_t write_callback(char *data, size_t size, size_t nmemb, void *userdata);
int inspection_scan(char **file_array, const int file_num, char ***str_array, int **paths_to_strings, char ***addresses, int **paths);
int extract_strings(const char *file, char ***str_array, int total_strs);
int extract_addresses(char **str_array, char ***addresses, int str_num, int *paths_to_strings, int **paths);
int check_duplicates(char **addresses, char *address, int addr_num, int length);
int check_malicious(char *address);



#endif