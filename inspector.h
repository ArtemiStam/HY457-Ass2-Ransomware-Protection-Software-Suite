#ifndef _INSPECTOR_H_
#include <regex.h> 

int inspection_scan(char **file_array, const int file_num, char ***str_array, char ***paths_to_strings);
int extract_strings(const char *file, char ***str_array, int total_strs);


#endif