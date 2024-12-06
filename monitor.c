#include "scanner.h"
#include "monitor.h"

struct inot_event {
    char *name;
    int type;
    int enable;
};

void event_listener(char *directory) {
    int fd, wd, poll_num, current_event = 0;
    nfds_t nfds;
    struct pollfd fds[2];
    char buf;
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    struct inot_event *events;

    if (directory == NULL)
    {
        status_update(1, "Invalid Directory");
        status_update(1, "Application Ended");
        exit(1);
    }

    printf("[%s] [%d] [%02d-%s-%02d %02d:%02d:%02d] Monitoring directory %s\n", "INFO", getpid(), date.tm_mday, MONTH_STRING[date.tm_mon], date.tm_year+1900, date.tm_hour, date.tm_min, date.tm_sec, directory);
    
    /* Create the file descriptor for accessing the inotify API. */
    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1)
    {
        status_update(1, "inotify_init failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    /* Allocate memory for watch descriptors. */
    wd = inotify_add_watch(fd, directory, IN_CREATE | IN_OPEN | IN_ACCESS | IN_MODIFY | IN_CLOSE | IN_DELETE); // Watch for events of type: create,open,access,modify,close,delete
    if (wd == -1)
    {
        status_update(1, "inotify_add_watch failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    events = (struct inot_event *) malloc (sizeof(struct inot_event)*1048576); //allocate memory for max number of events
    if (events == NULL)
    {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }

    /* Prepare for polling. */
    nfds = 2;
    fds[0].fd = STDIN_FILENO; /* Console input */
    fds[0].events = POLLIN;

    fds[1].fd = fd; /* Inotify input */
    fds[1].events = POLLIN;

    /* Wait for events and/or terminal input. */
    status_update(0, "Waiting for events...");
    while (1)
    {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1)
        {
            if (errno == EINTR)
                continue;
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0)
        {
            if (fds[0].revents & POLLIN) // Console input event occured
            {
                // Console input is available. Empty stdin and quit. 
                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n') // read event into buffer, event is enter quit
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN) // Inotify input event occured
            {
                /* Inotify events are available. */
                handle_events(fd, wd, 1, directory, events, &current_event);
            }
        }
    }
    inotify_rm_watch(fd, wd);
    free(events);
    close(fd);
}

void handle_events(int fd, int wd, int argc, char *directory, struct inot_event *events, int *current_event) {
    char buf[1048576]
        __attribute__((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    int i = 0;
    
    /* Loop while events can be read from inotify file descriptor. */
    while(1)
    {
        /* Read some events. */
        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN)
        {
            perror("read");
            exit(EXIT_FAILURE);
        }

        /*  If the nonblocking read() found no events to read, then
            it returns -1 with errno set to EAGAIN. In that case,
            we exit the loop.
        */
        if (len <= 0)
            break;
       
        
        /* Loop over all events in the buffer. */
        for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len)
        {
            event = (const struct inotify_event *)ptr;
            if (event->mask & IN_ISDIR) /* If event is about a directory ignore */
            {
                continue;
            }
            else /* Event is about a file */
            {
                /* Print event type and save events that could signify ransomware */
                if (event->mask & IN_CREATE)
                {
                    printf("File '%s' was created\n", event->name);
                    events[*current_event].name = malloc(strlen(event->name) + 1);
                    if (events[*current_event].name == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    strcpy(events[*current_event].name, event->name);
                    //events[(*current_event)++].type = IN_CREATE;
                    events[(*current_event)].type = IN_CREATE;
                    events[(*current_event)++].enable = 1;
                }

                if (event->mask & IN_OPEN)
                {
                    printf("File '%s' was opened\n", event->name);
                    events[*current_event].name = malloc(strlen(event->name) + 1);
                    if (events[*current_event].name == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    strcpy(events[*current_event].name, event->name);
                    //events[(*current_event)++].type = IN_OPEN;
                    events[(*current_event)].type = IN_OPEN;
                    events[(*current_event)++].enable = 1;
                }

                if (event->mask & IN_ACCESS)
                {
                    printf("File '%s' was accessed\n", event->name);
                }

                if (event->mask & IN_MODIFY)
                {
                    printf("File '%s' was modified\n", event->name);
                    events[*current_event].name = malloc(strlen(event->name) + 1);
                    if (events[*current_event].name == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    strcpy(events[*current_event].name, event->name);
                    //events[(*current_event)++].type = IN_MODIFY;
                    events[(*current_event)].type = IN_MODIFY;
                    events[(*current_event)++].enable = 1;
                }

                if (event->mask & IN_CLOSE_NOWRITE)
                {
                    printf("File '%s' that was not opened for writing was closed\n", event->name);
                }

                if (event->mask & IN_CLOSE_WRITE)
                {
                    printf("File '%s' that was opened for writing was closed\n", event->name);
                }

                if (event->mask & IN_DELETE)
                {
                    printf("File '%s' was deleted from watched directory\n", event->name);
                    events[*current_event].name = malloc(strlen(event->name) + 1);
                    if (events[*current_event].name == NULL)
                    {
                        status_update(1, "Memory Allocation Failed");
                        status_update(1, "Application Ended");
                        exit(1);
                    }
                    strcpy(events[*current_event].name, event->name);
                    //events[(*current_event)++].type = IN_DELETE;
                    events[(*current_event)].type = IN_DELETE;
                    events[(*current_event)++].enable = 1;

                    if (detect_ransomware(events,(const char *) event->name, *current_event)) { // After deletion of a file ransomware could occur
                        printf("\033[0;31m[WARN]  Ransomware attack detected on file %s\033[0m\n", event->name);
                    } 

                    for (i = 0; i < *current_event; i++)
                    {
                        if (!strcmp(events[i].name, event->name))
                        {
                            events[i].enable = 0;
                        }
                        
                    }
                    
                }
            }
        }
    }
}

int detect_ransomware(struct inot_event *events, const char *file_name, int num_events) {
    char *name_locked;
    int i, steps = 0;

    if (events == NULL || file_name == NULL)
    {
        status_update(1, "Invalid event list or file name");
        status_update(1, "Application Ended");
        exit(1);
    }

    /* Create file name appended with ".locked" */
    name_locked = malloc(strlen(file_name) + strlen(".locked") + 1);
    if (name_locked == NULL)
    {
        status_update(1, "Memory Allocation Failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    strcpy(name_locked, file_name);
    strcat(name_locked, ".locked");
    
    /* Search in reverse order for ransomware event sequence: delete file_name, modify file_name.locked, create file_name.locked, open file_name */
    for (i = num_events - 1; i >= 0 ; i--)
    {
        if (steps == 0 && !strcmp(events[i].name, file_name) && events[i].type == IN_DELETE && events[i].enable == 1)
            steps++;

        if (steps == 1 && !strcmp(events[i].name, name_locked) && events[i].type == IN_MODIFY && events[i].enable == 1)
            steps++;
        
        if (steps == 2 && !strcmp(events[i].name, name_locked) && events[i].type == IN_CREATE && events[i].enable == 1)
            steps++;

        if (steps == 3 && !strcmp(events[i].name, file_name) && events[i].type == IN_OPEN && events[i].enable == 1)
            steps++;

        if (steps >= 4) // Multiple modify or open events could occur so we test for steps > 4 and steps = 4.
            return 1;
    }
    
    return 0;
}

