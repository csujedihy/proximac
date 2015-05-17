#ifndef _UTILS_H
#define _UTILS_H
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <uv.h>
#include <signal.h>
extern FILE * logfile;

#if __GNUC__ >= 3
    #define likely(x) __builtin_expect(!!(x), 1)
    #define unlikely(x) __builtin_expect(!!(x), 0)
#else
    #define likely(x) (x)
    #define unlikely(x) (x)
#endif

#define TIME_FORMAT "%Y-%m-%d %H:%M:%S"
#define COLORDEF_GREEM \e[01;32m
#define COLORDEF_WHITE \e[0m
#define USE_LOGFILE(ident)                                      \
    do {                                                        \
        if (ident != NULL) { logfile = fopen(ident, "w+"); } }  \
    while (0)

#define CLOSE_LOGFILE                                           \
    do {                                                        \
        if (logfile != NULL) { fclose(logfile); } }             \
    while (0)

#define TRY_CLOSE(server_ctx, handle, cb)   do {               \
    if (!uv_is_closing((uv_handle_t*) &server_ctx->remote_handle)     \
    && !uv_is_closing((uv_handle_t*) &server_ctx->server_handle)) {   \
        uv_close((uv_handle_t*) handle, cb);      \
    }                                                          \
} while (0)

#define ERROR_UV(msg, code) do {                                                         \
    fprintf(stderr, "%s: [%s: %s]\n", msg, uv_err_name((code)), uv_strerror((code)));    \
    assert(0);                                                                           \
} while(0)

#define ERROR(msg) do {                                             \
    fprintf(stderr, "%s\n", msg);                                   \
    assert(0);                                                      \
} while(0)

#ifdef XCODE_DEBUG
#define LOGI(format, ...)                                   \
do {                                                        \
    time_t now = time(NULL);                                \
    char timestr[20];                                       \
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
    fprintf(stderr, " %s INFO: " format "\n", timestr,      \
    ## __VA_ARGS__);                                        \
    fflush(stderr);                                         \
}                                                           \
while (0)
#else
#define LOGI(format, ...)                                   \
do {                                                        \
    time_t now = time(NULL);                                \
    char timestr[20];                                       \
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
    fprintf(stderr, "\x1b[32m %s INFO: \e[0m" format "\n",  \
            timestr,## __VA_ARGS__);                        \
    fflush(stderr);                                         \
}                                                           \
while (0)
#endif

#ifdef XCODE_DEBUG
#define LOGW(format, ...)                                   \
do {                                                        \
    time_t now = time(NULL);                                \
    char timestr[20];                                       \
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));    \
    fprintf(stderr, " %s WARN: " format "\n",               \
    timestr,## __VA_ARGS__);                                \
    fflush(stderr);                                         \
}                                                           \
while (0)
#else
#define LOGW(format, ...)                                       \
do {                                                            \
    time_t now = time(NULL);                                    \
    char timestr[20];                                           \
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));        \
    if (logfile != NULL) {                                      \
        fprintf(logfile, " %s WARN: " format "\n", \
                timestr,## __VA_ARGS__);                        \
        fflush(logfile);                                        \
    }                                                           \
    else {                                                      \
        fprintf(stderr, "\x1b[33m %s WARN: \e[0m" format "\n",  \
                timestr,## __VA_ARGS__);                        \
        fflush(stderr);                                         \
    }                                                           \
}                                                               \
while (0)
#endif

#ifdef XCODE_DEBUG
#define LOGD(format, ...)                                                       \
do {                                                                            \
            time_t now = time(NULL);                                            \
            char timestr[20];                                                   \
            strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
            fprintf(stderr, " %s INFO: " format "\n", timestr,                  \
            ## __VA_ARGS__);                                                    \
            fflush(stderr);                                                     \
    }                                                                           \
while (0)
#else
#define LOGD(format, ...)                                                       \
do {                                                                            \
    if (logfile != NULL) {                                                  \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(logfile, " %s INFO: " format "\n", timestr,                 \
        ## __VA_ARGS__);                                                    \
        fflush(logfile);                                                    \
    }                                                                       \
    else {                                                                  \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(stderr, "\x1b[32m %s INFO: \e[0m" format "\n", timestr,     \
        ## __VA_ARGS__);                                                    \
        fflush(stderr);                                                     \
    }                                                                       \
}                                                                           \
while (0)
#endif

#define FATAL(format, ...)                                                  \
do {                                                                        \
    if (logfile != NULL) {                                                  \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(logfile, " %s FATAL: " format "\n", timestr,   \
        ## __VA_ARGS__);                                                    \
        fflush(logfile);                                                    \
    }                                                                       \
    else {                                                                  \
        time_t now = time(NULL);                                            \
        char timestr[20];                                                   \
        strftime(timestr, 20, TIME_FORMAT, localtime(&now));                \
        fprintf(stderr, "\x1b[31m %s FATAL: \e[0m" format "\n", timestr,    \
        ## __VA_ARGS__);                                                    \
        fflush(stderr);                                                     \
    }                                                                       \
    exit(EXIT_FAILURE);                                                     \
}                                                                           \
while (0)

#define LOGE(format, ...)                                                 \
do {                                                                      \
    time_t now = time(NULL);                                              \
    char timestr[20];                                                     \
    strftime(timestr, 20, TIME_FORMAT, localtime(&now));                  \
    if (logfile != NULL) {                                                \
        fprintf(logfile, " %s ERROR: " format "\n",          \
        timestr,## __VA_ARGS__);                                          \
        fflush(logfile);                                                  \
    }                                                                     \
    else {                                                                \
        fprintf(stderr, "\x1b[31m %s ERROR: \e[0m" format "\n",           \
        timestr,## __VA_ARGS__);                                          \
        fflush(stderr);                                                   \
    }                                                                     \
}                                                                         \
while (0)

#define SHOW_BUFFER(buf, len)   \
do {                            \
    for (int i = 0; i<len;i++)  \
        putchar(buf[i]);        \
} while (0)

#define LOG_SHOW_BUFFER(buf, len)               \
do {                                            \
    if (logfile != NULL) {                      \
        for (int i=0; i<len; i++)               \
            fprintf(logfile, "%c", buf[i]);     \
        fflush(logfile);                        \
    }                                           \
} while (0)                              

#define SHOW_BUFFER_IN_HEX(buf, len)    \
do {                                    \
    for (int i=0; i<len; i++)           \
    printf("%x_",buf[i]);               \
} while (0)

//packet related operations
#define set_header pkt_maker
#define set_payload pkt_maker
#define get_header pkt_access
#define get_payload pkt_access
#define get_id pkt_access_sid
#define pkt_maker(dest, src, len, offset)   \
do {                                        \
    memcpy(dest + offset, src, len);        \
    offset += len;                          \
}  while(0)

#define pkt_access(dest, src, len, offset)  \
do {                                        \
    memcpy(dest, src + offset, len);        \
    offset += len;                          \
}  while(0)

#define pkt_access_sid(ctx, dest, src, len, offset)                     \
do {                                                                    \
    pkt_access((dest), (src), (len), (offset));                         \
    (ctx)->packet.session_id = ntohl((uint32_t)ctx->packet.session_id); \
} while(0)

// built-in link list MACROs, originated from libcork
#define list_init(list)                 \
do {                                    \
    (list)->head.next = &(list)->head;  \
    (list)->head.prev = &(list)->head;  \
} while (0)

#define list_add_after(prev, elem)  \
do {                                \
    (elem)->prev = (prev);          \
    (elem)->next = (prev)->next;    \
    (prev)->next->prev = (elem);    \
    (prev)->next = (elem);          \
} while (0)

#define list_add_before(succ, elem) \
do {                                \
(elem)->prev = (succ)->prev;        \
(elem)->next = (succ);              \
(succ)->prev->next = (elem);        \
(succ)->prev = (elem);              \
} while (0)

#define list_add_to_tail(list, elem) \
list_add_before(&(list)->head, elem);

#define list_add_to_head(list, elem) \
list_add_after(&(list)->head, elem);

#define list_get_head_elem(list) \
(((list)->head.next == &(list)->head)? NULL: (list)->head.next)

#define list_remove_elem(elem)          \
do {                                    \
    (elem)->prev->next = (elem)->next;  \
    (elem)->next->prev = (elem)->prev;  \
} while (0)

#define list_get_start(list) \
((list)->head.next)

#define list_elem_is_end(list, element) \
((element) == &(list)->head)

void usage();
struct timeval GetTimeStamp();
void setup_signal_handler(uv_loop_t *loop);
void signal_handler(uv_signal_t *handle, int signum);
void init_daemon();
unsigned int hash(char *str);

#endif