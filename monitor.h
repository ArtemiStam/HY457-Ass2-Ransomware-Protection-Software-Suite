#ifndef _MONITOR_H_
#include <sys/inotify.h>
#include <poll.h>
#include <errno.h>

struct inot_event;

void event_listener(char *directory);
void handle_events(int fd, int wd, int argc, char *directory, struct inot_event *events, int *current_event);
int detect_ransomware(struct inot_event *events, const char *file_name, int num_events);

#endif