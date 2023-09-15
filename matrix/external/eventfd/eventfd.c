#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_EVENTS 10

int main() {
    int efd = epoll_create1(0);
    if (efd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }

    int event_fd = eventfd(0, EFD_NONBLOCK);
    if (event_fd == -1) {
        perror("eventfd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event event;
    event.data.fd = event_fd;
    event.events = EPOLLIN | EPOLLET;

    if (epoll_ctl(efd, EPOLL_CTL_ADD, event_fd, &event) == -1) {
        perror("epoll_ctl: event_fd");
        exit(EXIT_FAILURE);
    }

    struct epoll_event events[MAX_EVENTS];
    uint64_t value;

    while (1) {
        int n = epoll_wait(efd, events, MAX_EVENTS, -1);
        if (n == -1) {
            perror("epoll_wait");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == event_fd) {
                ssize_t nread = read(event_fd, &value, sizeof(value));
                if (nread != sizeof(value)) {
                    perror("read");
                    exit(EXIT_FAILURE);
                }
                printf("eventfd value: %lu\n", (unsigned long)value);
            }
        }
    }

    close(event_fd);
    close(efd);
    return 0;
}

