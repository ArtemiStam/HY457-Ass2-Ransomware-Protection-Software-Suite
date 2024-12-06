#ifndef _INSPECTOR_H_
#include <regex.h>      /*Needed to filter domains from file contents*/
#include <curl/curl.h>  /*Needed to send requests to Cloudflare if domain is malicious*/

/*Gets called when curllib receives response and writes the response to a Memory struct object */
size_t write_callback(char *data, size_t size, size_t nmemb, void *userdata);
/* Extracts the strings from all the files in file_array and inpsects them for malicious domains */
int inspection_scan(char **file_array, const int file_num, char ***str_array, int **paths_to_strings, char ***addresses, int **paths);
/* Extracts all the strings of length >= 4 from the give file */
int extract_strings(const char *file, char ***str_array, int total_strs);
/* Extracts all the domains from the str_array */
int extract_addresses(char **str_array, char ***addresses, int str_num, int *paths_to_strings, int **paths);
/* Check if the provided address/domain is has already been inserted in the addresses array */
int check_duplicates(char **addresses, char *address, int addr_num, int length);
/* Send a request to CloudFlares family DNS server to check if the provided address/domain is malicious */
int check_malicious(char *address);



#endif