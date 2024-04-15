#ifndef _MONITOR_H_
#include <sys/inotify.h>
#include <poll.h>
#include <errno.h>

void event_listener(char *directory);
void handle_events(int fd, int wd, int argc, char *directory);


#endif