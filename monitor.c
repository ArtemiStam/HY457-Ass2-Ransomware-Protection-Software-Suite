#include "scanner.h"
#include "monitor.h"


void event_listener(char *directory) {
    int fd, wd, poll_num;
    //struct inotify_event event_list;
    nfds_t nfds = 2;
    struct pollfd fds[2];
    char buf;
    time_t t = time(NULL);
    struct tm date = *localtime(&t);
    
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
    wd = inotify_add_watch(fd, directory, IN_CREATE | IN_OPEN | IN_ACCESS |IN_MODIFY | IN_DELETE);
    if (wd == -1 )
    {
        status_update(1, "inotify_add_watch failed");
        status_update(1, "Application Ended");
        exit(1);
    }
    
    /* Prepare for polling. */
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
            if (fds[0].revents & POLLIN)
            {
                // Console input is available. Empty stdin and quit. 
                while (read(STDIN_FILENO, &buf, 1) > 0 && buf != '\n')
                    continue;
                break;
            }

            if (fds[1].revents & POLLIN)
            {
                /* Inotify events are available. */

                handle_events(fd, wd, 1, directory);
            }
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
}

void handle_events(int fd, int wd, int argc, char * directory) {
    char buf[1048576]
        __attribute__((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    int i = 0;
    ssize_t len;

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
        while(i < len)//for (char *ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len)
        {
            i = 0;
            event = (const struct inotify_event *)&buf[i];
            if (event->len)
            {
                if (event->mask & IN_ISDIR)
                {
                    continue;
                }
                else
                {
                    // IN_CLOSE | IN_ACCESS | IN_OPEN | IN_CREATE | IN_MODIFY | IN_CLOSE_WRITE | IN_CLOSE_NOWRITE | IN_DELET
        
                    if (event->mask & IN_CREATE)
                    {
                        printf("File '%s' was created\n", event->name);
                        break;
                    }
                    if (event->mask & IN_OPEN) {
                        printf("File '%s' was opened\n", event->name);
                        break;
                    }
                    if (event->mask & IN_ACCESS) {
                        printf("File '%s' was accessed\n", event->name);
                        break;
                    }
                    if (event->mask & IN_MODIFY)
                    {
                       
                        printf("File '%s' was modified\n", event->name);
                        break;
                        
                    }
                    if (event->mask & IN_DELETE)
                    {
                        printf("File '%s' was deleted\n", event->name);
                        break;
                    }
                    i+= sizeof(struct inotify_event) + event->len;
                }
            }
            
        }
    }
}