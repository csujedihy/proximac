//
//  proximac.c
//  proximac
//
//  Created by jedihy on 15-5-17.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//
#include <stdbool.h>
#include <stdarg.h>
#include <mach/mach_types.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/lock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/kern_control.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <kern/assert.h>
#include <libkern/OSMalloc.h>
#include <netinet/in.h>
#include <string.h>


#include "tree.h"
#include "proximac.h"

// Global variables without lock protection
static kern_ctl_ref g_proximac_ctl_ref = NULL;
static int g_pid_num = 0;
static int g_proximac_mode = PROXIMAC_MODE_OFF;

static bool g_proximac_tcp_filter_registered = false;
static bool	g_proximac_tcp_unreg_started = false;
static bool	g_proximac_tcp_unreg_completed = false;

// R/W locks
static lck_grp_t * g_lock_grp = NULL;
static lck_rw_t * g_pidlist_lock = NULL;    // protect g_pid_num and pid_list
static lck_rw_t * g_mode_lock = NULL;

/* List of pid to free added for proximac */
SLIST_HEAD(pid_slist, pid);
static struct pid_slist pid_freelist;

/* Red-black tree of pid to be Hooked for proximac */
struct pid {
    RB_ENTRY(pid) rb_link;
    int pid;
    int value;
    SLIST_ENTRY(pid) slist_link;
};

RB_HEAD(pid_tree, pid);

static struct pid_tree pid_list;

static inline int
pid_cmp(const struct pid *tree_a, const struct pid *tree_b)
{
    if (tree_a->pid == tree_b->pid)
        return 0;
    return tree_a->pid < tree_b->pid? -1:1;
}

RB_PROTOTYPE(pid_tree, pid, rb_link, pid_cmp);
RB_GENERATE(pid_tree, pid, rb_link, pid_cmp);

// declare kernel init and exit functions
kern_return_t proximac_start(kmod_info_t * ki, void *data);
kern_return_t proximac_stop(kmod_info_t *ki, void *data);

// declare locks related functions
static errno_t init_locks();
static errno_t init_lock_grp();
static errno_t alloc_rwlock(lck_rw_t ** lock_ptr);

// declare controller callbacks
static errno_t proximac_ctl_connect_cb(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo);
static errno_t proximac_ctl_setopt_cb(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len);
static errno_t proximac_ctl_getopt_cb(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);

// declare filter related callbacks
static void
proximac_tcp_unregistered_cb(sflt_handle handle);
static errno_t
proximac_tcp_attach_cb(void ** cookie, socket_t so);
static void
proximac_tcp_detach_cb(void * cookie, socket_t so);
static errno_t
proximac_tcp_connect_out_cb(void * cookie, socket_t so, const struct sockaddr * to);
static	void
proximac_tcp_notify_cb(void *cookie, socket_t so, sflt_event_t event, void *param);

// other functions
static errno_t install_proximac_tcp_filter();
static errno_t uninstall_proximac_tcp_filter();

#pragma mark Customized printf function
#define LOGI(format, ...) do {                      \
printf("[Proximac]: " format "\n", ## __VA_ARGS__); \
} while (0)

#pragma mark Lock-related functions
static void
release_lock(lck_rw_t * lock)
{
    // Make sure g_lock_grp is not NULL
    assert(g_lock_grp);
    
    if (lock)
    {
        lck_rw_free(lock, g_lock_grp);
    }
}

static void
release_locks()
{
    if (g_mode_lock)
        release_lock(g_mode_lock);
    
    if (g_pidlist_lock)
        release_lock(g_pidlist_lock);
    
    g_mode_lock = g_pidlist_lock = NULL;
    
    if (g_lock_grp)
    {
        lck_grp_free(g_lock_grp);
        g_lock_grp = NULL;
    }
}

static errno_t
alloc_rwlock(lck_rw_t ** lock_ptr)
{
    errno_t retval = 0;
    lck_attr_t * lock_attr = NULL;
    
    // Make sure g_lock_grp is not NULL
    assert(g_lock_grp);
    
    lock_attr = lck_attr_alloc_init();
    if (NULL == lock_attr)
    {
        LOGI("lck_attr_alloc_init() failed");
        retval = ENOMEM;
        goto out;
    }
    
    *lock_ptr = lck_rw_alloc_init(g_lock_grp, lock_attr);
    if (NULL == *lock_ptr)
    {
        LOGI("lck_rw_alloc_init() failed");
        retval = ENOMEM;
        goto out;
    }
    
out:
    if (lock_attr)
        lck_attr_free(lock_attr);
    
    return retval;
}

static errno_t init_locks() {
    errno_t retval = 0;
    retval = init_lock_grp();
    if (retval) {
        LOGI("init_lock_grp error errorno = %d", retval);
        return retval;
    }
    
    retval = alloc_rwlock(&g_pidlist_lock);
    if (retval) {
        LOGI("alloc_rwlock error for g_pidlist_lock errorno = %d", retval);
        return retval;
    }
    
    retval = alloc_rwlock(&g_mode_lock);
    if (retval) {
        LOGI("alloc_rwlock for g_mode_lock error errorno = %d", retval);
        return retval;
    }
    
    return retval;
}

static errno_t init_lock_grp() {
    errno_t result = 0;
    
    // Lock group should be initialized only once.
    assert(NULL == g_lock_grp);
    
    lck_grp_attr_t * lock_grp_attr = lck_grp_attr_alloc_init();
    if (NULL == lock_grp_attr)
    {
        LOGI("lck_grp_attr_alloc_init() failed");
        result = ENOMEM;
        goto out;
    }
    
    g_lock_grp = lck_grp_alloc_init("proximac", lock_grp_attr);
    if (NULL == g_lock_grp)
    {
        LOGI("lck_grp_alloc_init() failed");
        result = ENOMEM;
        goto out;
    }
    
out:
    if (lock_grp_attr)
        lck_grp_attr_free(lock_grp_attr);
    
    return result;
}

#pragma mark Controller-related functions
static struct kern_ctl_reg proximac_ctl_reg = {
    MYBUNDLEID,				/* use a reverse dns name which includes a name unique to your comany */
    0,						/* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
    0,						/* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
    CTL_FLAG_PRIVILEGED,	/* privileged access required to access this filter */
    0,						/* use default send size buffer */
    0,						/* use default receive size buffer */
    proximac_ctl_connect_cb,	/* called when a connection request is accepted (requied field)*/
    NULL,					/* called when a connection becomes disconnected */
    NULL,					/* ctl_send_func - handles data sent from the client to kernel control */
    proximac_ctl_setopt_cb,	/* called when the user process makes the setsockopt call */
    proximac_ctl_getopt_cb					/* called when the user process makes the getsockopt call */
};

static errno_t install_proximac_controller() {
    errno_t retval = 0;
    
    if (g_proximac_ctl_ref) {
        LOGI("proximac controller is already installed");
        return 0;
    }

    retval = ctl_register(&proximac_ctl_reg, &g_proximac_ctl_ref);
    
    if (0 == retval) {
        LOGI("Controller has been installed successfully");
    }
    else
        LOGI("ctl_register fialed errorno = %d", retval);
    
    return retval;

}

static errno_t
uninstall_proximac_controller()
{
    errno_t retval = 0;
    
    if (g_proximac_ctl_ref)
    {
        retval = ctl_deregister(g_proximac_ctl_ref);
        if (retval)
        {
            LOGI("ctl_deregister() error errorno = %d", retval);
        }
        else
        {
            g_proximac_ctl_ref = NULL;
            LOGI("Proximac controller has been unregistered.");
        }
    }
    else
    {
        LOGI("Proximac controller has not been registered.");
    }
    return retval;
}

static errno_t proximac_ctl_connect_cb(
    kern_ctl_ref kctlref,
    struct sockaddr_ctl *sac,
    void **unitinfo)
{
    // just leave connect cb alone
    LOGI("connected to client");
    return 0;
}

#define PROXIMAC_ON 1
#define HOOK_PID 2
#define PIDLIST_STATUS 3
#define PROXIMAC_OFF 4

static errno_t proximac_ctl_setopt_cb(
    kern_ctl_ref kctlref,
    u_int32_t unit,
    void *unitinfo,
    int opt,
    void *data,
    size_t len)
{
    int retval = 0;
    int intval;
    switch (opt) {
        case PROXIMAC_ON:
            lck_rw_lock_exclusive(g_pidlist_lock);
            if (g_pid_num != 0) {
                
                struct pid *pid_tmp;
                RB_FOREACH(pid_tmp, pid_tree, &pid_list) {
                    SLIST_INSERT_HEAD(&pid_freelist, pid_tmp, slist_link);
                }
                
                while (!SLIST_EMPTY(&pid_freelist)) {
                    pid_tmp = SLIST_FIRST(&pid_freelist);
                    SLIST_REMOVE_HEAD(&pid_freelist, slist_link);
                    RB_REMOVE(pid_tree, &pid_list, pid_tmp);
                    if (pid_tmp)
                        _FREE(pid_tmp, M_TEMP);
                    g_pid_num--;
                }
                
                if (g_pid_num == 0)
                    LOGI("pid list is cleared\n");
                
            } else
                LOGI("empty pid list");
            
            lck_rw_unlock_exclusive(g_pidlist_lock);

            lck_rw_lock_exclusive(g_mode_lock);
            // install socket filters
            if (g_proximac_mode == PROXIMAC_MODE_OFF) {
                retval = install_proximac_tcp_filter();
                if (retval) {
                    LOGI("install TCP filters error errorno = %d", retval);
                    lck_rw_unlock_exclusive(g_mode_lock);
                    return retval;
                }
                g_proximac_mode = PROXIMAC_MODE_ON;
            }
            lck_rw_unlock_exclusive(g_mode_lock);

            break;
//        case PROXIMAC_OFF:
//            lck_rw_lock_exclusive(g_mode_lock);
//            g_proximac_mode = PROXIMAC_MODE_OFF;
//            lck_rw_unlock_exclusive(g_mode_lock);
//            retval = uninstall_proximac_tcp_filter();
//            LOGI("PROXIMAC_OFF cmd received ret = %d", retval);
//            return retval;
//            break;
        case HOOK_PID:
            if (len < sizeof(int)) {
                retval = EINVAL;
                break;
            }
            intval = *(int *)data;
            lck_rw_lock_exclusive(g_pidlist_lock);
            struct pid *pid_to_insert = _MALLOC(sizeof(struct pid), M_TEMP, M_WAITOK| M_ZERO);
            pid_to_insert->pid = intval;
            RB_INSERT(pid_tree, &pid_list, pid_to_insert);
            LOGI("client sets pid %d to be hooked\n", pid_to_insert->pid);
            g_pid_num++;
            lck_rw_unlock_exclusive(g_pidlist_lock);
            break;
            
        default:
            break;
    }

    return retval;
}

static errno_t proximac_ctl_getopt_cb(
    kern_ctl_ref kctlref,
    u_int32_t unit,
    void *unitinfo,
    int opt,
    void *data,
    size_t *len)
{
    errno_t retval = 0;
    size_t  valsize;
    void    *buf;
    switch (opt) {
        case PIDLIST_STATUS:
            valsize = min(sizeof(int), *len);
            lck_rw_lock_exclusive(g_pidlist_lock);
            LOGI("pid number = %d\n", g_pid_num);
            buf = &g_pid_num;
            lck_rw_unlock_exclusive(g_pidlist_lock);
            break;
        case HOOK_PID:
            valsize = min(sizeof(int), *len);
            lck_rw_lock_exclusive(g_pidlist_lock);
            struct pid *pid_tmp = NULL;
            int pidget_checksum = 0;
            RB_FOREACH(pid_tmp, pid_tree, &pid_list) {
                pidget_checksum += pid_tmp->pid;
            }
            lck_rw_unlock_exclusive(g_pidlist_lock);
            buf = &pidget_checksum;
            LOGI("pidget_checksum = %d\n", pidget_checksum);
            break;
        case PROXIMAC_OFF:
        {
            int result = 0;
            valsize = min(sizeof(int), *len);
            lck_rw_lock_exclusive(g_mode_lock);
            g_proximac_mode = PROXIMAC_MODE_OFF;
            lck_rw_unlock_exclusive(g_mode_lock);
            result = uninstall_proximac_tcp_filter();
            buf = &result;
            LOGI("PROXIMAC_OFF@getsockopt cmd received ret = %d", retval);
            break;
        }
        default:
            retval = ENOTSUP;
            break;
    }
    
    if (retval == 0) {
        *len = valsize;
        if (data != NULL)
            bcopy(buf, data, valsize);
    }
    
    return retval;
}

#pragma mark TCP filter related functions
typedef struct proximac_cookie {
    int pidhash_value;  /* pid hash value */
    union {
        struct sockaddr_in	addr4;		/* ipv4 remote addr */
        struct sockaddr_in6	addr6;		/* ipv6 remote addr */
    } remote_addr;
    int protocol;       /* IPv4 or IPv6 */
} proximac_cookie_t;

const static struct sflt_filter proximac_tcp_filter = {
    PROXIMAC_TCP_FILTER_HANDLE,     /* sflt_handle */
    SFLT_GLOBAL,                    /* sf_flags */
    MYBUNDLEID,                     /* sf_name - cannot be nil else param err results */
    proximac_tcp_unregistered_cb,   /* sf_unregistered_func */
    proximac_tcp_attach_cb,         /* sf_attach_func - cannot be nil else param err results */
    proximac_tcp_detach_cb,         /* sf_detach_func - cannot be nil else param err results */
    proximac_tcp_notify_cb,             /* sf_notify_func */
    NULL,                           /* sf_getpeername_func */
    NULL,                           /* sf_getsockname_func */
    NULL,                           /* sf_data_in_func */
    NULL,                           /* sf_data_out_func */
    NULL,                           /* sf_connect_in_func */
    proximac_tcp_connect_out_cb,	/* sf_connect_out_func */
    NULL,                           /* sf_bind_func */
    NULL,                           /* sf_setoption_func */
    NULL,                           /* sf_getoption_func */
    NULL,                           /* sf_listen_func */
    NULL                            /* sf_ioctl_func */
};

/* pid hash function */
unsigned int pid_hash(char *str)
{
    unsigned int h;
    unsigned char *p;
#define MULTIPLIER 33
    h = 0;
    for (p = (unsigned char*)str; *p != '\0'; p++)
        h = MULTIPLIER * h + *p;
    return h; // or, h % ARRAY_SIZE;
}


static void
proximac_tcp_detach_cb(void * cookie, socket_t so)
{
    assert(cookie);
    // free cookie
    _FREE(cookie, M_TEMP);
    LOGI("Proximac TCP filter has been detached from a socket");
}

static errno_t
proximac_tcp_connect_out_cb(
   void * cookie,
   socket_t so,
   const struct sockaddr * to)
{
    proximac_cookie_t * proximac_cookie = (proximac_cookie_t *)cookie;
    lck_rw_lock_shared(g_mode_lock);
    if (g_proximac_mode == PROXIMAC_MODE_OFF)
    {
        lck_rw_unlock_shared(g_mode_lock);
        return 0;
    }
    lck_rw_unlock_shared(g_mode_lock);
    
    assert(cookie);

    
    // Make sure address family is correct
    assert(to->sa_family == AF_INET);
    assert(sizeof(struct sockaddr_in) <= to->sa_len);
    assert((to->sa_family == AF_INET) || (to->sa_family == AF_INET6));	/*verify that the address is AF_INET/AF_INET6 */

    assert (sizeof(proximac_cookie->remote_addr.addr4) >= to->sa_len); /* verify that there is enough room to store data */
    /* save the remote address in the tli_remote field */
    bcopy(to, &(proximac_cookie->remote_addr.addr4), to->sa_len);
    struct sockaddr_in *remote_addr;
    remote_addr = (struct sockaddr_in*)to;
    proximac_cookie->remote_addr.addr4.sin_port = ntohs(proximac_cookie->remote_addr.addr4.sin_port);
    struct pid find_pid;
    find_pid.pid = proximac_cookie->pidhash_value;
    lck_rw_lock_exclusive(g_pidlist_lock);
    struct pid *exist = RB_FIND(pid_tree, &pid_list, &find_pid);
    LOGI("after RB_FIND pid = %d pid_num %d\n", find_pid.pid, g_pid_num);
    lck_rw_unlock_exclusive(g_pidlist_lock);
    if (exist != NULL) {
        LOGI("found existed PID\n");
        remote_addr->sin_port = htons(8558);
        remote_addr->sin_addr.s_addr = 0x100007f;
    }
    
    return 0;
}

static errno_t
proximac_tcp_attach_cb(void ** cookie, socket_t so)
{
    // Check proximac mode
    lck_rw_lock_shared(g_mode_lock);
    if (g_proximac_mode == PROXIMAC_MODE_OFF)
    {
        lck_rw_unlock_shared(g_mode_lock);
        return -1;
    }
    lck_rw_unlock_shared(g_mode_lock);
    
    // Allocate cookie for this socket
    *cookie = _MALLOC(sizeof(proximac_cookie_t), M_TEMP, M_WAITOK | M_ZERO);
    if (NULL == *cookie)
    {
        LOGI("_MALLOC() error");
        return ENOMEM;
    }
    
    proximac_cookie_t * proximac_cookie = (proximac_cookie_t *)(*cookie);
    char proc_name[64] = {0};
    proc_selfname(proc_name, 63);
    proximac_cookie->pidhash_value = pid_hash(proc_name);
    LOGI("pid hash value = %d\n", proximac_cookie->pidhash_value);
    LOGI("Proximac TCP filter has been attached to a socket");
    return 0;
}

static	void
proximac_tcp_notify_cb(void *cookie, socket_t so, sflt_event_t event, void *param) {
    proximac_cookie_t * proximac_cookie = (proximac_cookie_t *)cookie;
    switch (event) {
        case sock_evt_connected:
        {
            unsigned char	addrString[256];
            void			*remoteAddr;
            in_port_t		port;
            remoteAddr = &(proximac_cookie->remote_addr.addr4.sin_addr);
            port = proximac_cookie->remote_addr.addr4.sin_port;
            inet_ntop(AF_INET, remoteAddr, (char*)addrString, sizeof(addrString));

            // added prepend proximac_hdr for proximac
            struct pid find_pid;
            find_pid.pid = proximac_cookie->pidhash_value;
            lck_rw_lock_exclusive(g_pidlist_lock);
            struct pid *exist = RB_FIND(pid_tree, &pid_list, &find_pid);
            LOGI("notify_cb -- after RB_FIND pid = %d pid_num = %d\n", find_pid.pid, g_pid_num);
            lck_rw_unlock_exclusive(g_pidlist_lock);
            if (exist != NULL) {
                LOGI("notify_cb -- do hook operations to pid = %d\n", find_pid.pid);
                mbuf_t proximac_hdr_data = NULL;
                mbuf_t proximac_hdr_control = NULL;
                errno_t retval;
                
                char addrlen = strlen(addrString);
                LOGI("getsockopt addrString %s\n", addrString);
                int hdr_len = 1 + addrlen + sizeof(port);
                
                char* proximac_hdr = _MALLOC(hdr_len, M_TEMP, M_WAITOK| M_ZERO);
                proximac_hdr[0] = addrlen;
                memcpy(proximac_hdr + 1, addrString, addrlen);
                memcpy(proximac_hdr + 1 + addrlen, &port, sizeof(port));
                
                // Allocate a mbuf chain for adding proximac header.
                // Note: default type and flags are fine; don't do further modification.
                retval = mbuf_allocpacket(MBUF_WAITOK, hdr_len, 0, &proximac_hdr_data);
                retval = mbuf_copyback(proximac_hdr_data, 0, hdr_len, proximac_hdr, MBUF_WAITOK);
                _FREE(proximac_hdr, M_TEMP);
                retval = sock_inject_data_out(so, NULL, proximac_hdr_data, proximac_hdr_control, 0);
            }
            break;
        }
        default:
            break;
    }
}

static void
proximac_tcp_unregistered_cb(sflt_handle handle)
{
    assert(PROXIMAC_TCP_FILTER_HANDLE == handle);
    g_proximac_tcp_unreg_completed = true;
    g_proximac_tcp_filter_registered = false;
    LOGI("Proximac TCP filter has been unregistered.");
}

static errno_t
install_proximac_tcp_filter() {
    errno_t retval = 0;
    if (g_proximac_tcp_filter_registered)
    {
        LOGI("Proximac TCP filter is already installed.");
        return 0;
    }
    
    if (g_proximac_tcp_unreg_started && !g_proximac_tcp_unreg_completed)
    {
        LOGI("Proximac TCP filter is being uninstalled, try again!");
        return EAGAIN;		
    }
    
    if (!g_proximac_tcp_filter_registered)
    {
        // register the filter with PF_INET domain, SOCK_STREAM type, TCP protocol
        retval = sflt_register(&proximac_tcp_filter, PF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (retval == 0)
        {
            LOGI("Proximac TCP filter has been registered");
            g_proximac_tcp_filter_registered = true;
            g_proximac_tcp_unreg_started = false;
            g_proximac_tcp_unreg_completed = false;
        }
        else
        {
            LOGI("sflt_register failed errorno = %d", retval);
            return retval;
        }	
    }
    return retval;
}

static errno_t
uninstall_proximac_tcp_filter(void)
{
    errno_t retval;
    
    if (!g_proximac_tcp_filter_registered)
    {
        LOGI("Proximac TCP filter has not been installed.");
        return 0;
    }
    
    if (!g_proximac_tcp_unreg_started)
    {
        // start the unregistration process
        retval = sflt_unregister(PROXIMAC_TCP_FILTER_HANDLE);
        if (retval)
        {
            LOGI("sflt_unregister(PROXIMAC_TCP_FILTER_HANDLE) error errorno = %d", retval);
            return retval;
        }
        else
        {
            // Indicate that we've started the unreg process.
            g_proximac_tcp_unreg_started = true;
        }
    }
    
    if (!g_proximac_tcp_unreg_completed)
    {
        LOGI("Proximac TCP filter is being unregistered.");
        return EINPROGRESS;
    }	
    
    return 0;		
}

#pragma mark Kernel-related functions
kern_return_t proximac_start(kmod_info_t * ki, void *data)
{
    errno_t retval = 0;
    retval = init_locks();
    
    // initialize pid freelist and pidlist for proximac
    SLIST_INIT(&pid_freelist);
    RB_INIT(&pid_list);

    if (retval) {
        LOGI("locks init failed at module_start errorno = %d", retval);
        return KERN_RESOURCE_SHORTAGE;
    }
    
    retval = install_proximac_controller();
    if (retval) {
        LOGI("controller install error");
        goto fail;
    }
    return KERN_SUCCESS;
    
fail:
    release_locks();
    return KERN_FAILURE;
}

kern_return_t proximac_stop(kmod_info_t *ki, void *data)
{
    errno_t retval;
    lck_rw_lock_exclusive(g_mode_lock);
    g_proximac_mode = PROXIMAC_MODE_OFF;
    lck_rw_unlock_exclusive(g_mode_lock);
    
    retval = uninstall_proximac_tcp_filter();
    if (retval) {
        LOGI("uninstall Proximac TCP filters error errorno = %d", retval);
        return KERN_FAILURE;
    }
    
    retval = uninstall_proximac_controller();
    if (retval) {
        LOGI("uninstall Proximac controller error errorno = %d", retval);
        return KERN_FAILURE;
    }
    
    
    release_locks();
    LOGI("Proximac kext is now removed");
    return KERN_SUCCESS;
}
