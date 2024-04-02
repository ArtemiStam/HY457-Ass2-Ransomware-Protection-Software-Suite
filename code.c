#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>

int get_file_list(char *basePath, char ***file_list, int *num_files);

int main()
{
    // Directory path to list files
    char path[100];

    // Input path from user
    printf("Enter path to list files: ");
    scanf("%s", path);

    // Get the file list
    char **file_list;
    int num_files = 0;
    get_file_list(path, &file_list, &num_files);

    // Print the file list
    for (int i = 0; i < num_files; ++i)
    {
        printf("%s\n", file_list[i]);
    }

    // Free the file list
    free(file_list);

    return 0;
}

int get_file_list(char *basePath, char ***file_list, int *num_files)
{
    DIR *dir;
    struct dirent *entry;
    struct stat file_stat;
    int subdir_num_files = 0;
    int subdir_total_files = 0;
    char **subdir_file_list = NULL;

    if (!(dir = opendir(basePath)))
    {
        printf("Error: %s\n", basePath);
        return 0;
    }

    while ((entry = readdir(dir)) != NULL)
    {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
        {
            continue;
        }

        char path[1024];
        snprintf(path, sizeof(path), "%s/%s", basePath, entry->d_name);

        if (lstat(path, &file_stat) < 0)
        {
            printf("Error: %s\n", path);
            continue;
        }

        if (S_ISDIR(file_stat.st_mode))
        {
            // Recursively get the file list for subdirectories
            subdir_file_list = malloc(1024 * sizeof(char *));
            subdir_num_files = get_file_list(path, &subdir_file_list, &subdir_total_files);
        }
        else if (S_ISREG(file_stat.st_mode))
        {
            // Add the regular file to the file list
            ++*num_files;
            *file_list = realloc(*file_list, *num_files * sizeof(char *));
            *file_list[*num_files - 1] = malloc(strlen(entry->d_name) + 1);
            strcpy(*file_list[*num_files - 1], entry->d_name);
        }
    }

    // Add the file list for subdirectories to the total file list
    if (subdir_file_list != NULL)
    {
        *file_list = realloc(*file_list, (*num_files + subdir_total_files) * sizeof(char *));
        for (int i = 0; i < subdir_num_files; ++i)
        {
            *file_list[*num_files + i] = malloc(strlen(subdir_file_list[i]) + 1);
            strcpy(*file_list[*num_files + i], subdir_file_list[i]);
        }
        *num_files += subdir_num_files;
        free(subdir_file_list);
    }

    closedir(dir);

    return *num_files;
}