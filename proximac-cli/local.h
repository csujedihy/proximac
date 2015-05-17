#ifndef LOCAL_H_
#define LOCAL_H_

#define INT_MAX 2147483647
#define BUF_SIZE 2048
#define CTL_CLOSE 0x04
#define CTL_INIT 0x01
#define CTL_NORMAL 0

// packet related MACROs
#define MAX_PKT_SIZE 8192
#define ID_LEN 4
#define PKT_LEN 2
#define RSV_LEN 1
#define DATALEN_LEN 2
#define ATYP_LEN 1
#define ADDRLEN_LEN  1
#define PORT_LEN 2
#define HDR_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)
#define EXP_TO_RECV_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)

// remote connection status MACROs
#define RC_OFF 0
#define RC_ESTABLISHING 1
#define RC_OK 2
#define MAX_RC_NUM 32

// PF sockopt
#define PROXIMAC_ON 1
#define HOOK_PID 2
#define PIDLIST_STATUS 3
#define PROXIMAC_OFF 4

#include "tree.h"

struct pid {
    RB_ENTRY(pid) rb_link;
    int pid;
    char* name;
};

RB_HEAD(pid_tree, pid);
RB_PROTOTYPE(pid_tree, pid, rb_link, pid_cmp);
extern struct pid_tree pid_list;

int tell_kernel_to_hook();

typedef struct {
    uv_write_t req;
    uv_buf_t buf;
} write_req_t;

typedef struct {
    uv_tcp_t handle;
} listener_t;

struct remote_ctx;

typedef struct server_ctx{
    uv_tcp_t server_handle;
    uv_tcp_t remote_handle;
    int server_stage;
    int remote_stage;
    char remote_addr[256];
    char addrlen;
    uint16_t port;
    char* buf;
    int buf_len;
    struct remote_ctx* remote_ctx;
} server_ctx_t;

#endif