/*
(c) Copyright 2005 Apple Computer, Inc. All rights reserved.

IMPORTANT:  This Apple software is supplied to you by Apple Computer, Inc. (“Apple”) in 
consideration of your agreement to the following terms, and your use, installation, 
modification or redistribution of this Apple software constitutes acceptance of these 
terms.  If you do not agree with these terms, please do not use, install, modify or 
redistribute this Apple software.

In consideration of your agreement to abide by the following terms, and subject to 
these terms, Apple grants you a personal, non-exclusive license, under Apple’s copyrights 
in this original Apple software (the “Apple Software”), to use, reproduce, modify and 
redistribute the Apple Software, with or without modifications, in source and/or binary 
forms; provided that if you redistribute the Apple Software in its entirety and without 
modifications, you must retain this notice and the following text and disclaimers in all 
such redistributions of the Apple Software.  Neither the name, trademarks, service marks 
or logos of Apple Computer, Inc. may be used to endorse or promote products derived 
from the Apple Software without specific prior written permission from Apple.  Except 
as expressly stated in this notice, no other rights or licenses, express or implied, 
are granted by Apple herein, including but not limited to any patent rights that may
 be infringed by your derivative works or by other works in which the Apple Software 
 may be incorporated.

The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO 
WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES 
OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING 
THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS. 

IN NO EVENT SHALL APPLE BE LIABLE FOR ANY SPECIAL, INDIRECT, INCIDENTAL OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE 
GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING 
IN ANY WAY OUT OF THE USE, REPRODUCTION, MODIFICATION AND/OR DISTRIBUTION OF THE 
APPLE SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING 
NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.
*/
 
/* 
Sample network kernel extension written for the updated NKE KPI's for the OS X Tiger
release. This sample NKE will not run under OS X 10.3.x or earlier. The sample also
demonstrates communication with an application process using a SYSTEM_CONTROL socket.
 
 Change History
 1.3 - added IPv6 support and provide a workaround solution for the problem such that
	mbuf_tag_allocate foccasionally fails to tag outgoing IPv6 mbuf chains when the
	mbuf has no PKTHDR bit set in the lead mbuf. The workaround is to prepend an
	mbuf to the front of the chain, which does have the PKTHDR bit set. One cannot just 
	set the bit as there are internal structure settings which must be set properly
	for which there are no accessor functions provided.
 
	Make use of inet_ntop which is defined in Kernel.framework/Headers/netinet/in.h 
		under Mac OS X 10.4.x
 
 */

/*
   Theory of operation:
  
   At init time, we add ourselve to the list of socket filters for TCP.
   For each new connection (active or passive), we log the endpoint
   addresses, keep track of the stats of the conection and log the
   results and close time.
  
   At a minimum, the stats are: recv bytes, pkts; xmit bytes, pkts
   The stats and other info are kept in the extension control block that 
   is attached to a TCP socket when created.
   The stats are kept into two lists: one list for the active connections
   and one list for the closed connections.
  
   The stats for the closed connections can be read by an application using 
   a system control socket. In addition this sample shows how to use socket 
   options to apply and retrieve information over a system control socket.
   At init time, a system control socket is registered. The included tcptool
   finds the system control socket and communicates with the kernel extension
   thru this socket.
  
   An additional feature of the sample is to demonstrate packet swallowing and
   packet re-injection. As packet swallowing is enabled, for both the data_in 
   and data_out functions, all unprocessed packets are tagged and swallowed - 
   that is, these routines return
   the EJUSTRETURN result which tells the system to stop processing of the packet.
   To disable this functionality, set SWALLOW_PACKETS to 0. 
  
   Once the packet is swallowed, a timer routine is scheduled, which will re-inject the
   packet into the system for processing. A re-injected packet causes the corresponding
   data_in or data_out function to be called again to process the packet. In order to
   keep the function from swallowing the packet again, these functions check for the
   presence of a tag. The presence of the tag tells these functions that the packet has already
   been processed and to return with a result of 0 so that processing can continue on
   the packet. Note that if a module swallows the packet and re-inserts the
   packet, all modules of the same type will again see the packet. It is possible for a data_in/data_out 
   function to see the same packet more than once. For this reason, the tag mechanism makes
   more sense to detect previous processing rather than maintaining a list of
   "previous" processed mbuf pointers.
   
   When swallowing a packet, save the mbuf_t value, not the reference value passed to the
   sf_data_in_func/sf_data_out_func. The reference value to the mbuf_t parameter is no 
   longer valid upon return from the sf_data_in_func/sf_data_out_func.
 
   In the datain/out functions, as the mbuf_t is passed by reference, the NKE can split the
	contents of the mbuf_t, allowing the lead portion of the kext to be processed, and swallowing
    the tail portion. Other modifications can also be made to the mbuf_t as demonstrated in this
	sample. Refer to the prepend_mbuf_hdr function for an example.
   
   This sample also implements the use of the "Fine Grain Locking" api's provided in
   locks.h, as well as the OSMalloc call defined in <libkern/OSMalloc.h>.
   
   Note the following differences with this sample written for OS X 10.4.x to socket
   filters written for OS 10.3.x and earlier
   a. When calling OSMalloc, the WaitOK version can be used since memory allocation will
		not block packet processing.
   b. With fine grain locking support now present in the kernel, the Network funnel is no
		longer needed to serialize network access. The "Fine grain locking" calls are used to
		serialize access to the various queues defined to log socket information,
		control connection information, and to stored data_inbound and outbound swallowed packets.
		A call to lck_mtx_lock blocks until the mutex parameter is freed with a call to 
		lck_mtx_unlock.
		
 */
#include <mach/vm_types.h>
#include <mach/kmod.h>
#include <sys/socket.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_mbuf.h>
#include <sys/kpi_socket.h>
#include <sys/kpi_socketfilter.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/mbuf.h>
#include <netinet/in.h>
#include <kern/locks.h>
#include <kern/assert.h>
#include <kern/debug.h>
#include <libkern/tree.h>

#include "tcplogger.h"
#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <sys/kern_control.h>
#include <sys/kauth.h>
#include <sys/time.h>
#include <stdarg.h>

static int pid_to_hook = 0;
static int pid_num = 0;

#if !defined(SWALLOW_PACKETS)
#define SWALLOW_PACKETS		0 	// set this define to 1 to demonstrate all packet swallowing/re-injection
								// set this define to 0 for for simple filtering of data - no packet swallowing
#endif

#if !defined(SHOW_PACKET_FLOW)
#define SHOW_PACKET_FLOW	0	// set to 1 to have data_in/out routines show packet processing
#endif

#if !defined(DEBUG)
#define DEBUG	1				// DEBUG == 1 - print logging messsages to system.log
								// DEBUG == 0 - no logging messages.
#endif

#define kMY_TAG_TYPE	1

// values to use with the memory allocated by the tag function, to indicate which processing has been
// performed already.
typedef enum PACKETPROCFLAGS	{
	INBOUND_DONE	= 1,
	OUTBOUND_DONE
} PACKETPROCFLAGS;

#if SWALLOW_PACKETS
typedef enum DATATIMERSTATES {
	TIMER_INACTIVE = 0,
	TIMER_PENDING,
	TIMER_RUNNING
}DATATIMERSTATES;
#endif  // SWALLOW_PACKETS

static OSMallocTag		gOSMallocTag;	// tag for use with OSMalloc calls which is used to associate memory
							// allocations made with this kext. Preferred to using MALLOC and FREE

static boolean_t	gFilterRegistered_ip4 = FALSE;
static boolean_t	gFilterRegistered_ip6 = FALSE;
static boolean_t	gUnregisterProc_ip4_started = FALSE;
static boolean_t	gUnregisterProc_ip6_started = FALSE;
static boolean_t	gUnregisterProc_ip4_complete = FALSE;
static boolean_t	gUnregisterProc_ip6_complete = FALSE;
static boolean_t	gKernCtlRegistered = FALSE;
#if SWALLOW_PACKETS
static DATATIMERSTATES		gTimerState = TIMER_INACTIVE;	// used to prevent too many (extraneous) calls to bsd_timeout
#endif  // SWALLOW_PACKETS


/* List of pid to free added for proximac */
SLIST_HEAD(pid_list, pid);
static struct pid_list pid_freelist;

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

static lck_mtx_t		*gmutex_pid = NULL; // used to protect pid_list and pid_freelist


/* List of active 'Logging' sockets */
static struct tl_list tl_active;				// protected by gmutex

/* List of terminated TCPLogEntry structs, waiting for harvesting the information*/
static struct tl_list tl_done;					// protected by gmutex

/* Protect consistency of our data at entry points */
static lck_mtx_t		*gmutex = NULL;				// used to protect the tl_active and the tl_done queues
#if SWALLOW_PACKETS
static lck_mtx_t		*g_swallowQ_mutex = NULL;	// used to protect the queue where we place swallowed packets
#endif  // SWALLOW_PACKETS
static lck_grp_t		*gmutex_grp = NULL;

/* tag associated with this kext for use in marking packets that have been previously processed. */
static mbuf_tag_id_t	gidtag;

/*
 * Per socket extension control block for the log function
 */

struct TCPLogEntry {	
	TAILQ_ENTRY(TCPLogEntry)	tle_link;   /* link to next log entry item */
	socket_t					tle_so;		/* Pointer to owning socket */
	boolean_t					tle_active;
	boolean_t					tle_in_detach;
	struct TCPLogInfo			tle_info;
	uint32_t					numPktInDefer;
	uint32_t					magic;		/* magic value to ensure that system is passing me my buffer */
    uint32_t                    init;
};
typedef struct TCPLogEntry  TCPLogEntry;

#define kTCPLogEntryMagic		0xAABBCCDD
#define kTLCBEntryMagic			0xDDCCBBAA

TAILQ_HEAD(tl_list, TCPLogEntry);

/* the following are macros to access TCPLogInfo fields in the TCPLogEntry structure */
#define tle_len			tle_info.tli_len
#define tle_state		tle_info.tli_state
#define tle_genid		tle_info.tli_genid
#define tle_len			tle_info.tli_len
#define tle_bytes_in	tle_info.tli_bytes_in
#define tle_bufs_in		tle_info.tli_pkts_in
#define tle_bytes_out	tle_info.tli_bytes_out
#define tle_bufs_out	tle_info.tli_pkts_out
#define tle_create		tle_info.tli_create
#define tle_start		tle_info.tli_start
#define tle_stop		tle_info.tli_stop
#define tle_pid			tle_info.tli_pid
#define tle_uid			tle_info.tli_uid
#define tle_protocol	tle_info.tli_protocol

#define tle_local4 tle_info.tli_local.addr4
#define tle_remote4 tle_info.tli_remote.addr4
#define tle_local6 tle_info.tli_local.addr6
#define tle_remote6 tle_info.tli_remote.addr6

#if SWALLOW_PACKETS
/* the SwallowPktQueueItem record is used to store packet information when a packet is swallowed. The item is
  queued to the swallow_queue regardless of direction. The data_inbound flag determines which direction the swallowed
  packet will be processed. In a more complicated case it might be useful to implement separate queues
*/
struct SwallowPktQueueItem {
	TAILQ_ENTRY(SwallowPktQueueItem) tlq_next; /* link to next swallow queued entry or NULL */
	struct TCPLogEntry		*tlp;
	socket_t				so;
	mbuf_t					data;
	mbuf_t					control;
	boolean_t				data_inbound;
	sflt_data_flag_t		flags;
};

TAILQ_HEAD(swallow_queue, SwallowPktQueueItem);
static struct swallow_queue	swallow_queue;
#endif  // SWALLOW_PACKETS

/* Max # log entries to keep if not connected to reader */
#define TCPLOGGER_QMAX_DEFAULT	200
#define kInvalidUnit	0xFFFFFFFF

/*
	the tl_cb structure is used to track socket control requests to the kernel extension. Multiple processes
	could communicate with this socket filter and express an interest in contolling some aspect of the filter
	and/or requesting that the filter return connection information which this socket filter tracks.
*/
struct tl_cb {						
	TAILQ_ENTRY(tl_cb)  t_link;		// link to next control block record or NULL if end of chain.
	kern_ctl_ref		t_ref;		// control reference to the connected process
	u_int32_t			t_unit;		// unit number associated with the connected process
	u_int32_t			magic;		/* magic value to ensure that system is passing me my buffer */
	boolean_t			t_connected;
};

static kern_ctl_ref gctl_ref;


TAILQ_HEAD(tl_cb_list, tl_cb) ;		// definition of queue to store control block references. As each interested client
									// connects to this socket filter, a tl_cb structure is allocated to store information
									// about the connected process.
static struct tl_cb_list tl_cb_list;
static struct tl_stats tl_stats;

static void  tl_inactive(struct TCPLogEntry *tlp);
static void tl_send_done_log_info_to_clients(void);
static void tl_flush_backlog(boolean_t all);

/* =================================== */
#pragma mark  Utility Functions	

/*
 * Messages to the system log
 */

static void
tl_printf(const char *fmt, ...)
{
#if DEBUGX
//	va_list listp;
//	char log_buffer[92];
//
//	va_start(listp, fmt);
//
//	vsnprintf(log_buffer, sizeof(log_buffer), fmt, listp);
//	printf("%s", log_buffer);
//
//	va_end(listp);
#endif
}

#if SWALLOW_PACKETS
/*
	my_mbuf_freem is implemented to deal with the fact that the data_in and data_out functions are passed
	mbuf_t* parameters instead of mbuf_t parameters. The mbuf_freem routine can handle a null parameter, but
	the kext has to deal with the fact that it could be passed a NULL *mbuf_t parameter (normally the control
	parameter). 
*/
static void my_mbuf_freem(mbuf_t *mbuf)
{
	if (mbuf != NULL)
	{
		if (*mbuf != NULL)
		{
			mbuf_freem(*mbuf);
		}
	}
}
#endif  // SWALLOW_PACKETS


static errno_t alloc_locks(void)
{
	errno_t			result = 0;
	

    /* Allocate a mutex lock */
	/*
	 1. lck_grp_alloc_init allocates memory for the group lock and inits the lock with the
					group name and default attributes
	 For each individual lock
	2. lck_mtx_alloc_init allocates the memory for the lock and associates the 
			lock with the specified group.
	
	gmutex is used to lock access to the tl_active and tl_done queues. when the lock
		is active, the process has exclusive access to both queues.
	g_swallowQ_mutex used to lock access to the swallow_queue
	*/
	
	// for the name, use the reverse dns name associated with this
	// kernel extension
	gmutex_grp = lck_grp_alloc_init(MYBUNDLEID, LCK_GRP_ATTR_NULL);
	if (gmutex_grp == NULL)
	{
		tl_printf("error calling lck_grp_alloc_init\n");
		result = ENOMEM;
	}
	
	if (result == 0)
	{
		gmutex = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
		if (gmutex == NULL)
		{
			tl_printf("error calling lck_mtx_alloc_init\n");
			result = ENOMEM;
		}
        
        // added lock alloc for proximac
        gmutex_pid = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
        if (gmutex_pid == NULL)
        {
            tl_printf("error calling lck_mtx_alloc_init\n");
            result = ENOMEM;
        }
        
#if SWALLOW_PACKETS
		if (result == 0)
		{
			/* allocate the lock for use on processing items in the output queue */
			g_swallowQ_mutex = lck_mtx_alloc_init(gmutex_grp, LCK_ATTR_NULL);
			if (g_swallowQ_mutex == NULL)
			{
				tl_printf("error calling lck_mtx_alloc_init\n");
				result = ENOMEM;
			}
		}
#endif  // SWALLOW_PACKETS
	}
	
	return result;	// if we make it here, return success
}

static void free_locks(void)
{
	if (gmutex)
	{
		lck_mtx_free(gmutex, gmutex_grp);
		gmutex = NULL;
	}
    
    // added lock free for proximac
    if (gmutex_pid)
    {
        lck_mtx_free(gmutex_pid, gmutex_grp);
        gmutex_pid = NULL;
    }
    
#if SWALLOW_PACKETS
	if (g_swallowQ_mutex)
	{
		lck_mtx_free(g_swallowQ_mutex, gmutex_grp);
		g_swallowQ_mutex = NULL;
	}
#endif  // SWALLOW_PACKETS
	if (gmutex_grp)
	{
		lck_grp_free(gmutex_grp);
		gmutex_grp = NULL;
	}
}

#if defined(NDEBUG)
#define TCPLogEntryFromCookie(cookie) ((struct TCPLogEntry *) cookie)
#define tl_cb_EntryFromUnitInfo(cookied) ((struct tl_cb *) cookie)
#else
static struct TCPLogEntry * TCPLogEntryFromCookie(void *cookie)
{
	struct TCPLogEntry * result;
	result = (struct TCPLogEntry *) cookie;
	assert(result != NULL);
	assert(result->magic == kTCPLogEntryMagic);
	return result;
}
static struct tl_cb * tl_cb_EntryFromUnitInfo(void *unitinfo)
{
	struct tl_cb *result;
	result = (struct tl_cb *) unitinfo;
	assert(result != NULL);
	assert(result->magic == kTLCBEntryMagic);
	return result;
}
#endif

/*
	prepend_mbuf_hdr - used to prepend an mbuf_t init'd for PKTHDR so that an mbuf_tag_allocate
		call can be used to mark an mbuf. As per <rdar://problem/4786262>, on AFPoverIP IPv6 connections,
		very infrequently, the mbuf does not have the PKTHDR bit set and the mbuf_tag_allocate function fails. 
		A workaround solution is to prepend a PKTHDR mbuf to the front of the mbuf chain, so that the mbuf can be 
		"tagged"
 
	data - pointer to mbuf_t variable which has no PKTHDR bit set in the flags field
	len  - amount of data in the data mbuf chain

	return 0 (KERN_SUCCESS - success, the PKTHDR mbuf was successfully allocated and prepended to the front of the mbuf
			  and data now points to the newly allocated mbuf_t.
			  
	return any other value - failure, the PKTHDR mbuf_t failed to be allocated. 
 */
static errno_t
prepend_mbuf_hdr(mbuf_t *data, size_t pkt_len)
{
	mbuf_t			new_hdr;
	errno_t			status;

	status = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &new_hdr);
	if (KERN_SUCCESS == status)
	{
		/* we've created a replacement header, now we have to set things up */
		/* set the mbuf argument as the next mbuf in the chain */
		mbuf_setnext(new_hdr, *data);
		
		/* set the next packet attached to the mbuf argument in the pkt hdr */
		mbuf_setnextpkt(new_hdr, mbuf_nextpkt(*data));
		/* set the total chain len field in the pkt hdr */
		mbuf_pkthdr_setlen(new_hdr, pkt_len);
		mbuf_setlen(new_hdr, 0);

		mbuf_pkthdr_setrcvif(*data, NULL);
		
		/* now set the new mbuf_t as the new header mbuf_t */
		*data = new_hdr;
	}
	return status;
}

/*
	CheckTag - see if there is a tag associated with the mbuf_t with the matching bitmap bits set in the
				memory associated with the tag. Use global gidtag as id Tag to look for
	input m - pointer to mbuf_t variable on which to search for tag
			module_id - the tag_id obtained from the mbuf_tag_id_find call;
			tag_type - specific tagType to look for
			value - see if the tag_ref field has the expected value
	return 1 - success, the value in allocated memory associated with tag gidtag has a matching value
	return 0 - failure, either the mbuf_t is not tagged, or the allocated memory does not have the expected value
	Note that in this example, the value of tag_ref is used to store bitmap values. the allocated memory is
			process specific. 
 
*/
static int	CheckTag(mbuf_t *m, mbuf_tag_id_t module_id, mbuf_tag_type_t tag_type, PACKETPROCFLAGS value)
{
	errno_t	status;
	int		*tag_ref;
	size_t	len;
	
	// Check whether we have seen this packet before.
	status = mbuf_tag_find(*m, module_id, tag_type, &len, (void**)&tag_ref);
	if ((status == 0) && (*tag_ref == value) && (len == sizeof(value)))
		return 1;
		
	return 0;
}

/*	
	 - Set the tag associated with the mbuf_t with the bitmap bits set in bitmap
	The SetTag calls makes a call to mbuf_tag_allocate with the MBUF_WAITOK flag set. Under OS X 10.4, waiting for the 
	memory allocation is ok from within a filter function.
	10//06 - for AFPoverIP IPv6 connections, there are some packets which are passed which do not have the 
		PKTHDR bit set in the mbug_flags field. This will cause the mbuf_tag_allocate function to fail with
		EINVAL error. 
	
	input m - mbuf_t pointer variable on which to search for tag
			module_id - the tag_id obtained from the mbuf_tag_id_find call;
			tag_type - specific tagType to look for
			value - value  to set in allocated memory
	return 0 - success, the tag has been allocated and for the mbuf_t and the value has been set in the
				allocated memory. 
		   anything else - failure	
*/
static errno_t	SetTag(mbuf_t *data, mbuf_tag_id_t id_tag, mbuf_tag_type_t tag_type, PACKETPROCFLAGS value)
{	
	errno_t status;
	int		*tag_ref = NULL;
	size_t	len;
	
	assert(data);
	// look for existing tag
	status = mbuf_tag_find(*data, id_tag, tag_type, &len, (void*)&tag_ref);
	// allocate tag if needed
	if (status != 0) 
	{		
		status = mbuf_tag_allocate(*data, id_tag, tag_type, sizeof(value), MBUF_WAITOK, (void**)&tag_ref);
		if (status == 0)
			*tag_ref = value;		// set tag_ref
		else if (status == EINVAL)
		{			
			mbuf_flags_t	flags;
			// check to see if the mbuf_tag_allocate failed because the mbuf_t has the M_PKTHDR flag bit not set
			flags = mbuf_flags(*data);
			if ((flags & MBUF_PKTHDR) == 0)
			{
				mbuf_t			m = *data;
				size_t			totalbytes = 0;

				/* the packet is missing the MBUF_PKTHDR bit. In order to use the mbuf_tag_allocate, function,
					we need to prepend an mbuf to the mbuf which has the MBUF_PKTHDR bit set.
					We cannot just set this bit in the flags field as there are assumptions about the internal
					fields which there are no API's to access.
				*/
				tl_printf("mbuf_t missing MBUF_PKTHDR bit\n");

				while (m)
				{
					totalbytes += mbuf_len(m);
					m = mbuf_next(m);	// look at the next mbuf
				}
				status = prepend_mbuf_hdr(data, totalbytes);
				if (status == KERN_SUCCESS)
				{
					status = mbuf_tag_allocate(*data, id_tag, tag_type, sizeof(value), MBUF_WAITOK, (void**)&tag_ref);
					if (status)
					{
						tl_printf("mbuf_tag_allocate failed a second time, status was %d\n", status);
					}
				}
			}
		}
		else
			tl_printf("mbuf_tag_allocate failed, status was %d\n", status);
	}
	return status;
}

#if SWALLOW_PACKETS
/*
	FreeDeferredData - used to scan the swallow_queue and free the mbuf_t's that match to the 
					input socket_t so parameter. The queue item is also released.
*/
static void FreeDeferredData(socket_t so)
{
	struct SwallowPktQueueItem	*tlq;
	struct SwallowPktQueueItem	*tlqnext;

	assert(so);		// check that so is not null
	lck_mtx_lock(g_swallowQ_mutex);	// allow only a single entry into the function at a time
									// protect access to the swallow_queue
	for (tlq = TAILQ_FIRST(&swallow_queue); tlq != NULL; tlq = tlqnext)
	{
		// get the next element pointer before we potentially corrupt it

		tlqnext = TAILQ_NEXT(tlq, tlq_next);
		// look for a match, if we find it, move it from the deferred 
		// data queue to our local queue

		if (tlq->so == so)
		{

			if (tlq->data_inbound) 
				tl_printf("*********INBOUND PACKET FREED FROM SWALLOW QUEUE!!!!!!!! socket_t is 0x%X\n", so);
			else
				tl_printf("*********OUTBOUND PACKET FREED FROM SWALLOW QUEUE!!!!!!!! socket_t is 0x%X\n", so);

			TAILQ_REMOVE(&swallow_queue, tlq, tlq_next);
			my_mbuf_freem(&tlq->data);
			my_mbuf_freem(&tlq->control);
			OSFree(tlq, sizeof(struct SwallowPktQueueItem), gOSMallocTag);
		}
	}
	lck_mtx_unlock(g_swallowQ_mutex);
}

/*
	ReinjectDeferredData is used to scan the swallow_queue for packets to reinject in the stack.
	input parameter so - NULL indicates to match all packets in the swallow queue and force them to
						be re-injected
						non-NULL - match only those packets associated with the socket_t so parameter.
	Note: there is a potential timing issue. If the user forces the kext to be unloaded in the middle of 
		a data transfer, the kext will not get the normal notify messages - sock_evt_disconnecting and
		sock_evt_disconnected. As such, the system will go straight to calling the detach_fn. It could be
		that the data_timer has just fired and the ReinjectDeferredData routine has managed to move 
		packets from the swallow_queue to the packets_to_inject. If the detach_fn is called at this point,
		it can clear the packets that might have been moved into the swallow queue via the FreeDeferredData call
		above, but packets in the packets_to_inject queue will not be freed and will cause the 
		sock_inject_data_in/out functions to be called using a potentially invalid socket reference.
		For this reason, there is code in the ReinjectDeferredData and in the detach_fn to check
		whether there are still packet to be processed. If this occurs, a semaphore like system using msleep and
		wakeup will allow the detach_fn to wait until ReinjectDeferredData has completed processing for
		data on the socket_t ref that is being detached.
		
	Note: the use of the packets_to_inject queue is to make it so that the g_swallowQ_mutex does not need to
		held across the sock_inject_data_in/out calls. The g_swallowQ_mutex lock is only held while moving packets
		from the swallow_queue to the local packets_to_inject queue. Then the lock is released. 
		A lock should never be held across system calls since one never knows whether the same lock will be accessed 
		within the system call.
*/
static void
ReinjectDeferredData(socket_t so)
{
	struct swallow_queue		packets_to_inject;
	struct SwallowPktQueueItem	*tlq;
	struct SwallowPktQueueItem	*tlqnext;
	struct TCPLogEntry			*tlp;
	errno_t						result;
	
	// init the queue which we use to place the packets we want to re-inject into the tcp stream
	TAILQ_INIT(&packets_to_inject);

	lck_mtx_lock(g_swallowQ_mutex);	// allow only a single entry into the function at a time
									// protect access to the swallow_queue
	// iterate the queue looking for matching entries; if we find a match, 
	// remove it from queue and put it on packets_to_inject; because we're 
	// removing elements from tl_deferred_data, we can't use TAILQ_FOREACH
	for (tlq = TAILQ_FIRST(&swallow_queue); tlq != NULL; tlq = tlqnext)
	{
		// get the next element pointer before we potentially corrupt it

		tlqnext = TAILQ_NEXT(tlq, tlq_next);
		// look for a match, if we find it, move it from the deferred 
		// data queue to our local queue

		if ( (so == NULL) || (tlq->so == so) )
		{
			TAILQ_REMOVE(&swallow_queue, tlq, tlq_next);
			TAILQ_INSERT_TAIL(&packets_to_inject, tlq, tlq_next);
			tlp = tlq->tlp;		// get the log entry associated with this item
			tlp->numPktInDefer++;	// track the number of packets associated with this
									// socket put into inject queue - access to this field
									// protected by the g_swallowQ_mutex lock
		} 
	}
	// we're done with the global list, so release our lock on it
	lck_mtx_unlock(g_swallowQ_mutex);

	// now process the local list, injecting each packet we found
	while ( ! TAILQ_EMPTY(&packets_to_inject) )
	{
		tlq = TAILQ_FIRST(&packets_to_inject);
		TAILQ_REMOVE(&packets_to_inject, tlq, tlq_next);
		tlp = tlq->tlp;		/* get the log entry associated with this packet */
		/* inject the packet, in the right direction  */
		if (tlq->data_inbound) 
		{
			// NOTE: for TCP connections, the "to" parameter is NULL. For a UDP connection, there will likely be a valid
			// destination required. For the UDP case, you can use a pointer to local storage to pass the UDP sockaddr
			// setting. Refer to the header doc for the sock_inject_data_out function
			result = sock_inject_data_in(tlq->so, NULL, tlq->data, tlq->control, tlq->flags);
		}
		else
		{
			// NOTE: for TCP connections, the "to" parameter is NULL. For a UDP connection, there will likely be a valid
			// destination required. For the UDP case, you can use a pointer to local storage to pass the UDP sockaddr
			// setting. Refer to the header dock for the sock_inject_data_out function
			result = sock_inject_data_out(tlq->so, NULL, tlq->data, tlq->control, tlq->flags);
		}

		/* if the inject failed, check whether the data is inbound or outbound. As per the
			sock_inject_data_out description - The data and control values are always freed 
			regardless of return value. However, for the sock_inject_data_in function -  If the 
			function returns an error, the caller is responsible for freeing the mbuf.
		*/
		if (result)
		{
			printf("error calling sock_inject_data_in/out, dropping data - result was %dn", result);
			if (tlq->data_inbound) 
			{	
				/*
					only release mbuf for inbound injection failure
				*/
				mbuf_freem(tlq->data);
				mbuf_freem(tlq->control);
			}
		}
		// free the queue entry
		OSFree(tlq, sizeof(struct SwallowPktQueueItem), gOSMallocTag);

		lck_mtx_lock(g_swallowQ_mutex);		// limit access to tlp fields
		tlp->numPktInDefer--;		// decrement the number of packets associated with this socket being processed
		assert(tlp->numPktInDefer >= 0);
		if ((tlp->tle_in_detach) && (tlp->numPktInDefer <= 0))	// is the socket in the detach_fn which if true means that it is
																// in msleep waiting for the wakeup call.
		{
			lck_mtx_unlock(g_swallowQ_mutex); // release the lock before calling wakeup
			wakeup(&(tlp->numPktInDefer));
		}
		else
		{
			lck_mtx_unlock(g_swallowQ_mutex);
		}
	}

	// we don't need to do anything to tidy up packets_to_inject because 
	// a) the queue head is a local variable, and b) the queue elements 
	// are all gone (guaranteed by the while loop above).

}

/*
	data_timer - timer routine used to demonstrate processing of swallowed packets at a point different
		from the context of the data_in/out function. this routine checks for swallowed packets stored in
		swallow_queue and calls ReinjectDeferredData to re-inject them into the appropriate stream. 
		Note that this routine already assumes that 
		the packets have been tagged since the data_in/out functions will be called to process these
		re-injected packets.
*/
static void
data_timer(void * unused)
{
	boolean_t	done = FALSE;

//	tl_printf("entered data_timer\n");
	lck_mtx_lock(g_swallowQ_mutex);	// only allow one access at a time to gTimerState
	gTimerState = TIMER_RUNNING;	// clear the flag which indicates there is a scheduled data_timer call pending
	lck_mtx_unlock(g_swallowQ_mutex);
	while (done == FALSE)
	{
		ReinjectDeferredData(NULL);
		lck_mtx_lock(g_swallowQ_mutex);		// only allow one access at a time to gTimerState
		if (gTimerState == TIMER_RUNNING)
		{
			// the timer has not been scheduled by either data_in/out function.
			// If the data_in/out function had scheduled the timer, gTimerState would be TIMER_PENDING instead.
			gTimerState = TIMER_INACTIVE;
			done = TRUE;
		}
		else
		{
			gTimerState = TIMER_RUNNING;	// reset the timerstate to RUNNING since it had been moved to pending
		}
		lck_mtx_unlock(g_swallowQ_mutex);
	}
}

#endif	// #if SWALLOW_PACKETS

/* =================================== */
#pragma mark Socket Filter Functions

/*!
	@typedef sf_unregistered_func
	
	@discussion sf_unregistered_func is called to notify the filter it
		has been unregistered. This is the last function the stack will
		call and this function will only be called once all other
		function calls in to your filter have completed. Once this
		function has been called, your kext may safely unload.
	@param handle The socket filter handle used to identify this filter.
*/
static	void
tl_unregistered_fn_ip4(sflt_handle handle)
{
	gUnregisterProc_ip4_complete = TRUE;
	gFilterRegistered_ip4 = FALSE;
	tl_printf("tl_unregistered_func_ip4 entered\n");
}

static	void
tl_unregistered_fn_ip6(sflt_handle handle)
{
	gUnregisterProc_ip6_complete = TRUE;
	gFilterRegistered_ip6 = FALSE;
	tl_printf("tl_unregistered_func_ip6 entered\n");
}


/*!
	@typedef sf_attach_func_locked
	
	@discussion sf_attach_func_locked is called by both sf_attach_funcs initialize internel
		memory structures - assumption that the fine grain lock associated with the
		tl_active queue is held so that the queue entry can be inserted atomically.
	@param cookie Used to allow the socket filter to set the cookie for
		this attachment.
	@param so The socket the filter is being attached to.
			tlp - pointer to ths log entry structure to be associated with this
			socket reference for future socket filter calls
	@result - assumes that no problem will occur.
*/
static	void
tl_attach_fn_locked(socket_t so, struct TCPLogEntry *tlp)
{ 		
	tl_stats.tls_info++;
	bzero(tlp, sizeof (*tlp));
	tlp->tle_len = sizeof (*tlp);
	if (++tl_stats.tls_active > tl_stats.tls_active_max)
		tl_stats.tls_active_max = tl_stats.tls_active;
	tl_stats.tls_inuse++;
	tlp->tle_genid = ++tl_stats.tls_attached;
	tlp->tle_so = so;
	tlp->tle_active = TRUE;
	tlp->tle_in_detach = FALSE;
	tlp->magic = kTCPLogEntryMagic;	// set the magic cookie for debugging purposes only to verify that the system 
									// only returns memory that I allocated.
	microtime(&(tlp->tle_create));	/* Record start time for later */
	microtime(&(tlp->tle_start));	/* Record start time for later */
	
	// attach time is a good time to identify the calling process ID. 
	// could also make the proc_self call to obtain the proc_t value which is useful
	// to get the ucred structure.
	// important note: the pid associated with this socket is the pid of the process which created the 
	// socket. The socket may have been passed to another process with a different pid.
	tlp->tle_pid = proc_selfpid();
    printf("roc_selfpid() %d\n", proc_selfpid());
	// get the uid
	tlp->tle_uid = kauth_getuid();
	TAILQ_INSERT_TAIL(&tl_active, tlp, tle_link);
}

/*!
@typedef sf_attach_func
	
	@discussion sf_attach_func is called to notify the filter it has
 been attached to a new TCP socket. The filter may allocate memory for
 this attachment and use the cookie to track it. This filter is
 called in one of two cases:
 1) You've installed a global filter and a new socket was created.
 2) Your non-global socket filter is being attached using the SO_NKE
 socket option.
	@param cookie Used to allow the socket filter to set the cookie for
 this attachment.
	@param so The socket the filter is being attached to.
	@result If you return a non-zero value, your filter will not be
 attached to this socket.
 */

static	errno_t
tl_attach_fn_ip4(void **cookie, socket_t so)
{
    struct TCPLogEntry *tlp;
	errno_t				result = 0;
	
    tl_printf("tl_attach_fn_ip4  - so: 0x%X\n", so);	
	
	if (tl_stats.tls_enabled != 0)
	{
		/* use new OSMalloc call which makes it easier to track memory allocations under Tiger */
		/* this call can block */
		tlp = (struct TCPLogEntry *)OSMalloc(sizeof (struct TCPLogEntry), gOSMallocTag);
		if (tlp == NULL) 
		{
			return ENOBUFS;
		}
        
		/* save the log entry as the cookie associated with this socket ref */
		*(struct TCPLogEntry**)cookie = tlp;
		lck_mtx_lock(gmutex);	// take the lock so that we can protect against the tlp structure access
								// until after we complete our current access
		/* do not set tlp fields until after return from tl_attach_fn_locked as it
		   clears the tlp structure */
		tl_attach_fn_locked(so, tlp);
        tlp->init = 0;
		tlp->tle_protocol = AF_INET;		/* indicate that this is an IPv4 connection */
		lck_mtx_unlock(gmutex);
	}
	else
	{
		*cookie = NULL;
		/* return an error so that the socket filter is disassociated with this socket.
		   which means that the remaining socket filter calls will not be entered for activity on this socket. */
		result = ENXIO;
	}
	
	return result;
}

static	errno_t
tl_attach_fn_ip6(void **cookie, socket_t so)
{ 
	struct TCPLogEntry *tlp;
	errno_t				result = 0;
	
    tl_printf("tl_attach_fn_ip6  - so: 0x%X\n", so);	
	
	if (tl_stats.tls_enabled != 0)
	{
		// use new OSMalloc call which makes it easier to track memory allocations under Tiger
		tlp = (struct TCPLogEntry *)OSMalloc(sizeof (struct TCPLogEntry), gOSMallocTag);
		if (tlp == NULL) 
		{
			return ENOBUFS;
		}
		// save the log entry as the cookie associated with this socket ref
		*(struct TCPLogEntry**)cookie = tlp;	
		lck_mtx_lock(gmutex);	// take the lock so that we can protect against the tlp structure access
								// until after we complete our current access
		// do not set tlp fields until after return from tl_attach_fn_locked as it
		// clears the tlp structure
		tl_attach_fn_locked(so, tlp);
		tlp->tle_protocol = AF_INET6;		/* indicate that this is an IPv6 connection */
		lck_mtx_unlock(gmutex);
	}
	else
	{
		*cookie = NULL;
		// return an error so that the socket filter is disassociated with this socket.
		// which means that the remaining socket filter calls will not be entered for activity on this socket.
		result = ENXIO;
	}
	
	return result;
}

/*
	@typedef sf_detach_func
	
	@discussion sf_detach_func is called to notify the filter it has
		been detached from a socket. If the filter allocated any memory
		for this attachment, it should be freed. This function will
		be called when the socket is disposed of.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@result If you return a non-zero value, your filter will not be
		attached to this socket.
*/
static void	
tl_detach_fn4(void *cookie, socket_t so)
{
	struct TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);
	struct timeval now, timediff;
#if SWALLOW_PACKETS
	boolean_t			done = FALSE;
#endif  // SWALLOW_PACKETS

	tl_printf("tl_detach_fn_ipv4 - so: 0x%X, ", so);
	if (tlp == NULL)
		goto bail;

	microtime(&now);	/* Record stop time */
	timersub(&now, &(tlp->tle_start), &timediff);
	tlp->tle_stop = now;		
	if (tl_stats.tls_log > 0) 
	{
		tl_printf("duration %d.%6d sec, in: %d pkts, %d bytes, out: %d pkts, %d bytes\n", 
				timediff.tv_sec, timediff.tv_usec, tlp->tle_bufs_in, tlp->tle_bytes_in,
				tlp->tle_bufs_out, tlp->tle_bytes_out);
	}
	
#if SWALLOW_PACKETS
	/* It could be that the kernel extension is forcibly unloaded while it is actively transferring
	   data - for example in the middle of transferring data, the nke is unloaded. In this case, the
	   notify_fn will not be called with either the sock_evt_disconnecting, nor the sock_evt_disconnected
	   events to be able to force cleanup of the swallowed packets. Need to make sure that
	   all swallowed packets associated with this socket_t reference are deleted, before the detach_fn
	   returns. Following the detach_fn, the socket reference is no lnoger valid. and any calls which use
	   the "detached" socket_t reference could panic the system.
	*/
	FreeDeferredData(so);
	/*
		It could be that there is still some swallowed packet that are in the packets_to_inject
		queue when we cleared the DeferredData.
	*/
	while (done == FALSE)
	{
		int	numPktsInDefer;
		
		lck_mtx_lock(g_swallowQ_mutex);		// set lock to access the numPktInDefer field
		numPktsInDefer = tlp->numPktInDefer;
		assert(numPktsInDefer >= 0);
		if (numPktsInDefer == 0)
		{
			// this is the normal processing state
			done = TRUE;
			lck_mtx_unlock(g_swallowQ_mutex);	// release the lock
		}
		else
		{
			// I'd like to know if this code ever executes. Theoretically, it's possible.
			tl_printf("packets present in ReinjectDeferredData queue - it's great that we have code to protect against this possibility\n");
			tlp->tle_in_detach = TRUE;	// lock still held at this point.
			// there are still packets to inject queue to process
			// use msleep to wait for the for the wakeup call from ReinjectDeferredData
			// pass in PDROP flag so that the g_swallowQ_mutex is not retaken on return
			msleep(&tlp->numPktInDefer, g_swallowQ_mutex, PDROP, "tl_detach_fn4", 0);
			// we've been re-awaken which means that tlp->numPktInDefer should now be zero
			// so loop back in the while loop
		}
	}
#endif  // SWALLOW_PACKETS
	tl_inactive(tlp);
	tl_send_done_log_info_to_clients();

bail:

	return;
}

static void	
tl_detach_fn6(void *cookie, socket_t so)
{
	struct TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);
	struct timeval now, timediff;
#if SWALLOW_PACKETS
	boolean_t			done = FALSE;
#endif  // SWALLOW_PACKETS
	
	tl_printf("tl_detach_fn_ipv6 - so: 0x%X, ", so);
	if (tlp == NULL)
		goto bail;
	
	microtime(&now);	/* Record stop time */
	timersub(&now, &(tlp->tle_start), &timediff);
	tlp->tle_stop = now;		
	if (tl_stats.tls_log > 0) 
	{
		tl_printf("duration %d.%6d sec, in: %d pkts, %d bytes, out: %d pkts, %d bytes\n", 
				  timediff.tv_sec, timediff.tv_usec, tlp->tle_bufs_in, tlp->tle_bytes_in,
				  tlp->tle_bufs_out, tlp->tle_bytes_out);
	}
	
#if SWALLOW_PACKETS
	/* 
		If we have registered both ipv4 and ipv6 socket filters, then we can be expected to 
	 enter the detach function twice. 
	 
	 It could be that the kernel extension is forcibly unloaded while it is actively transferring
	 data - for example in the middle of transferring data, the nke is unloaded. In this case, the
	 notify_fn will not be called with either the sock_evt_disconnecting, nor the sock_evt_disconnected
	 events to be able to force cleanup of the swallowed packets. Need to make sure that
	 all swallowed packets associated with this socket_t reference are deleted, before the detach_fn
	 returns. Following the detach_fn, the socket reference is no lnoger valid. and any calls which use
	 the "detached" socket_t reference could panic the system.
	 */
	FreeDeferredData(so);
	/*
	 It could be that there is still some swallowed packet that are in the packets_to_inject
	 queue when we cleared the DeferredData.
	 */
	while (done == FALSE)
	{
		int	numPktsInDefer;
		
		lck_mtx_lock(g_swallowQ_mutex);		// set lock to access the numPktInDefer field
		numPktsInDefer = tlp->numPktInDefer;
		assert(numPktsInDefer >= 0);
		if (numPktsInDefer == 0)
		{
			// this is the normal processing state
			done = TRUE;
			lck_mtx_unlock(g_swallowQ_mutex);	// release the lock
		}
		else
		{
			// I'd like to know if this code ever executes. Theoretically, it's possible.
			tl_printf("packets present in ReinjectDeferredData queue - it's great that we have code to protect against this possibility\n");
			tlp->tle_in_detach = TRUE;	// lock still held at this point.
										// there are still packets to inject queue to process
										// use msleep to wait for the for the wakeup call from ReinjectDeferredData
										// pass in PDROP flag so that the g_swallowQ_mutex is not retaken on return
			msleep(&tlp->numPktInDefer, g_swallowQ_mutex, PDROP, "tl_detach_fn6", 0);
			// we've been re-awaken which means that tlp->numPktInDefer should now be zero
			// so loop back in the while loop
		}
	}
#endif  // SWALLOW_PACKETS
	tl_inactive(tlp);
	tl_send_done_log_info_to_clients();
	
bail:
		
		return;
}

/*
	@typedef sf_notify_func
	
	@discussion sf_notify_func is called to notify the filter of various
		state changes and other events occuring on the socket.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param event The type of event that has occurred.
	@param param Additional information about the event.
*/
static	void	
tl_notify_fn(void *cookie, socket_t so, sflt_event_t event, void *param)
{		
	struct	TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);

	if ((tlp->tle_state) == 0)
		tl_printf("unknown state ");

	switch (event)
	{
		case sock_evt_connecting:
//#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_connecting so: 0x%X, ", so);
//#endif
			if (tl_stats.tls_log > 0) 
			{
				unsigned char	addrString[256];
				void			*srcAddr;
				in_port_t		port;
				
									
				if (tlp->tle_protocol == AF_INET)
				{
					/* check to see if we have obtained the local socket address */
					if (tlp->tle_local4.sin_len == 0)
					{
						sock_getsockname(so, (struct sockaddr*)&(tlp->tle_local4), sizeof(tlp->tle_local4));
						tlp->tle_local4.sin_port = ntohs( tlp->tle_local4.sin_port);
					}
						/* if an error occurs, well we tried, but it's nothing to cause us to stop. */
					port = tlp->tle_local4.sin_port;
					srcAddr = &(tlp->tle_local4.sin_addr);
				}
				else	/* then it's an AF_INET6 connection */
				{
					/* check to see if we have obtained the local socket address */
					if (tlp->tle_local6.sin6_len == 0)
					{
						sock_getsockname(so, (struct sockaddr*)&(tlp->tle_local6), sizeof(tlp->tle_local6));  
						tlp->tle_local6.sin6_port = ntohs( tlp->tle_local6.sin6_port);
					}
					/* if an error occurs, well we tried, but it's nothing to cause us to stop. */
					port = tlp->tle_local6.sin6_port;
					srcAddr = &(tlp->tle_local6.sin6_addr);
				}
				inet_ntop(tlp->tle_protocol, srcAddr, (char*)addrString, sizeof(addrString));
//#if SHOW_PACKET_FLOW
				tl_printf("Local Addr: %s:%d\n", addrString, port);
//#endif
			}														
			break;

		case sock_evt_connected:
//#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_connected  so: 0x%X, ", so);
//#endif
			/* Called when TWH is complete.  Record start time */
			microtime(&(tlp->tle_start));	/* Record start time for later */

			if (tl_stats.tls_log > 0)
			{
				unsigned char	addrString[256];
				void			*remoteAddr;
				in_port_t		port;

				// output the address of the remote connection
				if (tlp->tle_protocol == AF_INET)
				{
					remoteAddr = &(tlp->tle_remote4.sin_addr);
					port = tlp->tle_remote4.sin_port;
				}
				else
				{
					remoteAddr = &(tlp->tle_remote6.sin6_addr);
					port = tlp->tle_remote6.sin6_port;
				}
				inet_ntop(tlp->tle_protocol, remoteAddr, (char*)addrString, sizeof(addrString));
//#if SHOW_PACKET_FLOW
				tl_printf("Remote Addr: %s:%d\n", addrString, port);
//#endif
                
                // added prepend proximac_hdr for proximac
                struct pid find_pid;
                find_pid.pid = tlp->tle_pid;
                lck_mtx_lock(gmutex_pid);
                struct pid *exist = RB_FIND(pid_tree, &pid_list, &find_pid);
                lck_mtx_unlock(gmutex_pid);
                printf("[proximac]: after RB_FIND pid = %d\n", find_pid.pid);
                if (exist != NULL) {
                    printf("[proximac]: do hook operations to pid = %d\n", find_pid.pid);
                    mbuf_t proximac_hdr_data = NULL;
                    mbuf_t proximac_hdr_control = NULL;
                    errno_t retval;
                    
                    char addrlen = strlen(addrString);
                    printf("getsockopt addrString %s\n", addrString);
                    int hdr_len = 1 + addrlen + sizeof(port);
                    
                    char* proximac_hdr = OSMalloc(hdr_len, gOSMallocTag);
                    proximac_hdr[0] = addrlen;
                    memcpy(proximac_hdr + 1, addrString, addrlen);
                    memcpy(proximac_hdr + 1 + addrlen, &port, sizeof(port));
                    
                    // Allocate a mbuf chain for adding proximac header.
                    // Note: default type and flags are fine; don't do further modification.
                    retval = mbuf_allocpacket(MBUF_WAITOK, hdr_len, 0, &proximac_hdr_data);
                    retval = mbuf_copyback(proximac_hdr_data, 0, hdr_len, proximac_hdr, MBUF_WAITOK);
                    OSFree(proximac_hdr, hdr_len, gOSMallocTag);
                    retval = sock_inject_data_out(so, NULL, proximac_hdr_data, proximac_hdr_control, 0);
                }
 			}
			break;

		case sock_evt_disconnecting:
			// If you have swallowed packets and are still holding onto a packet, this would
			// be a good place to force the swallowed packets out - before returning
			// from this routine.
#if SWALLOW_PACKETS
			ReinjectDeferredData(so);
#endif  // SWALLOW_PACKETS
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_disconning so: 0x%X\n", so);
#endif
			break;

		case sock_evt_disconnected:
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_disconn  - so: 0x%X\n", so);
#endif
			break;

		case sock_evt_flush_read:
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_flush_rd - so: 0x%X\n", so); 
#endif
			break;

		case sock_evt_shutdown:
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_shutdown - so: 0x%X\n", so); 
#endif
			break;
		
		case sock_evt_cantrecvmore:
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_cantrec  - so: 0x%X\n", so); 
#endif
			break;
		
		case sock_evt_cantsendmore:
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_cantsen  - so: 0x%X\n", so); 
#endif
			break;
		
		case sock_evt_closing:
#if SHOW_PACKET_FLOW
			tl_printf("sock_evt_closing  - so: 0x%X\n", so); 
#endif
			break;
		
		default:
#if SHOW_PACKET_FLOW
			tl_printf("unknown event     - so: 0x%X evt: %d\n", so, event); 
#endif
			break;
	}
}

/* 
	Notes for both the sf_data_in_func and the sf_data_out_func implementations.
	For these functions, the mbuf_t parameter is passed by reference. The kext can 
	manipulate the mbuf such as prepending an mbuf_t, splitting the mbuf and saving some
	tail portion of data, etc. As a reminder, you are responsible to ensure that
	data is processed in the correct order that is is received. If the kext splits the 
	mbuf_t, and returns the lead portion of data, then return KERN_SUCCESS, even though
	the nke swallows the tail portion.
 */
/*!
	@typedef sf_data_in_func
	
	@discussion sf_data_in_func is called to filter incoming data. If
		your filter intercepts data for later reinjection, it must queue
		all incoming data to preserve the order of the data. Use
		sock_inject_data_in to later reinject this data if you return
		EJUSTRETURN. Warning: This filter is on the data path, do not
		block or spend excessive time.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param from The addres the data is from, may be NULL if the socket
		is connected.
	@param data The data being received. Control data may appear in the
		mbuf chain, be sure to check the mbuf types to find control
		data.
	@param control Control data being passed separately from the data.
	@param flags Flags to indicate if this is out of band data or a
		record.
	@result Return:
		0 - The caller will continue with normal processing of the data.
		EJUSTRETURN - The caller will stop processing the data, the data will not be freed.
		Anything Else - The caller will free the data and stop processing.
		
		Note: as this is a TCP connection, the "from" parameter will be NULL - for UDP, the
		"from" field will point to a valid sockaddr structure. In this case, you must copy
		the contents of the "from" field to local memory when swallowing the packet so that
		you have a valid sockaddr to pass in the inject call.
*/
static	errno_t	
tl_data_in_fn(void *cookie, socket_t so, const struct sockaddr *from,
		mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
	struct TCPLogEntry			*tlp = (struct TCPLogEntry *) cookie;
	uint32_t					totalbytes;
	errno_t						result;

	if (from)
		tl_printf("ERROR - from field not NULL!!!!!!!!!!!!!!!!!!!");
	
	/* check whether we have seen this packet previously */
	if (CheckTag(data, gidtag, kMY_TAG_TYPE, INBOUND_DONE))
	{
#if SHOW_PACKET_FLOW
		tl_printf("tl_data_in_fn     - bypass so: 0x%08X, mbuf_t: 0x%08X\n", so, *data );
#endif
		/* we have processed this packet previously since out tag was attached.
			bail on further processing
		*/		
		return 0;
	}

#if SWALLOW_PACKETS
#if SHOW_PACKET_FLOW
	tl_printf("tl_data_in_fn     - so: 0x%X data: 0x%X swallow ", so, *data);
#endif
#else
#if SHOW_PACKET_FLOW
	tl_printf("tl_data_in_fn     - so: 0x%X data: 0x%X pass ", so, *data);
#endif
#endif  // SWALLOW_PACKETS
	/*
		If we reach this point, then we have not previously seen this packet. 
		First lets get some statistics from the packet.
	*/

	if (tl_stats.tls_log > 0)
	{
		totalbytes = mbuf_pkthdr_len(*data);
		OSIncrementAtomic((SInt32*)&(tlp->tle_bufs_in));		// increment packet count
		OSAddAtomic(totalbytes, (SInt32 *)&(tlp->tle_bytes_in));
	}
	
#if SHOW_PACKET_FLOW
	tl_printf("buff size: %d bytes.\n", totalbytes);
#endif

	/*
		If we swallow the packet and later re-inject the packet, we have to be
		prepared to see the packet through this routine once again. In fact, if
		after re-injecting the packet, another nke swallows and re-injects the packet
		we will see the packet an additional time. Rather than cache the mbuf_t reference
		we tag the mbuf_t and search for it's presence which we have already done above
		to decide if we have processed the packet.
		
		even for code which does not swallow packets, it's useful to set a tag on the packet to
		know that whether the packet has been previously processed or not.
	*/
	result = SetTag(data, gidtag, kMY_TAG_TYPE, INBOUND_DONE);
	if (result == 0)
	{
#if SWALLOW_PACKETS
		struct SwallowPktQueueItem	*tlq;
		struct timespec				ts;

		// use new OSMalloc call which makes it easier to track memory allocations under Tiger
		tlq = (struct SwallowPktQueueItem *)OSMalloc(sizeof (struct SwallowPktQueueItem), gOSMallocTag);
		if (tlq)
		{
			tlq->so = so;
			tlq->flags = flags;
			if (data == NULL)
				tlq->data = NULL;
			else
				tlq->data = *data;
			if (control == NULL)
				tlq->control = NULL;
			else
				tlq->control = *control;
			tlq->data_inbound = TRUE;
			tlq->tlp = tlp;		// store the logentry
			
			lck_mtx_lock(g_swallowQ_mutex);
			// queue the item into the input queue for processing when the timer fires
			TAILQ_INSERT_TAIL(&swallow_queue, tlq, tlq_next);	
			lck_mtx_unlock(g_swallowQ_mutex);

			/*
				IMPORTANT NOTE: Each call to bsd_timeout uses up an internal call resource
				until the timeout function executes. Too many calls to bsd_timeout could
				result in the panic "_internal_call_allocate" which results when all
				of the resources have been used up. The data_timer function processes all packets
				in the queue. Only issue the bsd_timeout if there is no call pending.
			*/

			lck_mtx_lock(g_swallowQ_mutex);
			if (gTimerState == TIMER_INACTIVE)
			{
				// initiate timer action in 1 microsec - we use the bsd_timeout finction for this
				// purpose.
				ts.tv_sec = 0;
				ts.tv_nsec = 100;
				gTimerState = TIMER_PENDING;
				lck_mtx_unlock(g_swallowQ_mutex);
				bsd_timeout(data_timer, NULL, &ts);
//				tl_printf("tl_data_in - bsd_timeout called\n");
			}
			else
			{
				// the timer has already been scheduled or is presently running, so no need to schedule - 
				// just mark the state as pending and it will indicate to the timer routine to run one more time.
				gTimerState = TIMER_PENDING;
				lck_mtx_unlock(g_swallowQ_mutex);
			}
			result = EJUSTRETURN;
		}
		else
		{
			tl_printf("Bad Error - failed to allocate memory for data_inbound queue item, will return ENOMEM\n");
			result = ENOMEM;
		}
#endif	// #if SWALLOW_PACKETS
	}
	else
	{
		// if the tag can't be allocated, drop the packet since we won't be able to recognize 
		// that the packet has been previously processed. More importantly, if we've swallowed the
		// previous packets, returning noErr is bad since this packet could be inserted
		// into the stream ahead of a packet which it's supposed to follow.
		tl_printf("Bad Error - SetTag returned an error %d\n", result);
		result = ENOMEM;
	}
//	tl_printf("tl_data_in returning result %d\n", result);
	return result;
}

/*!
	@typedef sf_data_out_func
	
	@discussion sf_data_out_func is called to filter outbound data. If
		your filter intercepts data for later reinjection, it must queue
		all outbound data to preserve the order of the data when
		reinjecting. Use sock_inject_data_out to later reinject this
		data. Warning: This filter is on the data path, do not block or
		spend excessive time.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param from The address the data is from, may be NULL if the socket
		is connected.
	@param data The data being received. Control data may appear in the
		mbuf chain, be sure to check the mbuf types to find control
		data.
	@param control Control data being passed separately from the data.
	@param flags Flags to indicate if this is out of band data or a
		record.
	@result Return:
		0 - The caller will continue with normal processing of the data.
		EJUSTRETURN - The caller will stop processing the data, the data will not be freed.
		Anything Else - The caller will free the data and stop processing.
		
		Note: as this is a TCP connection, the "to" parameter will be NULL - for UDP, the
		"to" field will point to a valid sockaddr structure. In this case, you must copy
		the contents of the "to" field to local memory when swallowing the packet so that
		you have a valid sockaddr to pass in the inject call.
*/
static	errno_t	
tl_data_out_fn(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data,
		mbuf_t *control, sflt_data_flag_t flags)
{
	struct TCPLogEntry		*tlp = (struct TCPLogEntry *) cookie;
	uint32_t				totalbytes;
	errno_t					result;
    
	if (to) /* see description above */
		tl_printf("ERROR - to field not NULL!!!!!!!!!!!!!!!!!!!");


//    for (mbuf_t mb = *data; mb; mb = mbuf_next(mb))
//    {
//        unsigned char* dataString = mbuf_data(mb);
//        size_t len = mbuf_len(mb);
//        for (size_t i = 0; i < len; i++)
//        {
//            printf("%c", dataString[i]);
//        }
//    }
//    printf("\n-------------\n");
    
	/* check whether we have seen this packet previously */
	if (CheckTag(data, gidtag, kMY_TAG_TYPE, OUTBOUND_DONE))
	{
#if SHOW_PACKET_FLOW
		tl_printf("tl_data_out_fn    - bypass so: 0x%08X, mbuf_t: 0x%08X\n", so, *data );
#endif  // SWALLOW_PACKETS
		/* we have processed this packet previously since out tag was attached.
			bail on further processing
		*/
		return 0;
	}
	/*
		If we reach this point, then we have not previously seen this packet. 
		First lets get some statistics from the packet.
	*/

#if !SWALLOW_PACKETS
#if SHOW_PACKET_FLOW
	tl_printf("tl_data_out_fn    - so: 0x%X data: 0x%X pass ", so, *data);
#endif
#else
#if SHOW_PACKET_FLOW
	tl_printf("tl_data_out_fn    - so: 0x%X data: 0x%X swallow ", so, *data);
#endif
#endif  // SWALLOW_PACKETS
	if (tl_stats.tls_log > 0)
	{
		totalbytes = mbuf_pkthdr_len(*data);
		OSIncrementAtomic((SInt32*)&(tlp->tle_bufs_out));		// increment packet count
		OSAddAtomic(totalbytes, (SInt32 *)&(tlp->tle_bytes_out));
	}

#if SHOW_PACKET_FLOW
	tl_printf("bytes in buffer: %d bytes\n", mbuf_pkthdr_len(*data));
#endif
	
	/*
		If we swallow the packet and later re-inject the packet, we have to be
		prepared to see the packet through this routine once again. In fact, if
		after re-injecting the packet, another nke swallows and re-injects the packet
		we will see the packet an additional time. Rather than cache the mbuf_t reference
		we tag the mbuf_t and search for it's presence which we have already done above
		to decide if we have processed the packet.
	*/
	result = SetTag(data, gidtag, kMY_TAG_TYPE, OUTBOUND_DONE);
	if (result == 0)
	{
#if SWALLOW_PACKETS
		struct SwallowPktQueueItem	*tlq;
		struct timespec			ts;
		// use new OSMalloc call which makes it easier to track memory allocations under Tiger
		tlq = (struct SwallowPktQueueItem *)OSMalloc(sizeof (struct SwallowPktQueueItem), gOSMallocTag);
		if (tlq)
		{
			tlq->so = so;
			tlq->flags = flags;
			if (data == NULL)
				tlq->data = NULL;
			else
				tlq->data = *data;
			if (control == NULL)
				tlq->control = NULL;
			else
				tlq->control = *control;
			tlq->data_inbound = FALSE;
			tlq->tlp = tlp;		// store the logentry for use in the deferred task
			
			lck_mtx_lock(g_swallowQ_mutex);
			// queue the item into the output queue for processing when the timer fires
			TAILQ_INSERT_TAIL(&swallow_queue, tlq, tlq_next);	
			lck_mtx_unlock(g_swallowQ_mutex);
			
			/*
				IMPORTANT NOTE: Each call to bsd_timeout uses up an internal call resource
				until the timeout function executes. Too many calls to bsd_timeout could
				result in the panic "_internal_call_allocate" which results when all
				of the resources have been used up. The data_timer function processes all packets
				in the queue. Only issue the bsd_timeout if there is no call pending.
			*/

			lck_mtx_lock(g_swallowQ_mutex);
			if (gTimerState == TIMER_INACTIVE)
			{
				// initiate timer action in 1 microsec - we use the bsd_timeout finction for this
				// purpose.
				ts.tv_sec = 0;
				ts.tv_nsec = 100;
				gTimerState = TIMER_PENDING;
				lck_mtx_unlock(g_swallowQ_mutex);
				bsd_timeout(data_timer, NULL, &ts);
			}
			else
			{
				// the timer has already been scheduled or is presently running, so no need to schedule - 
				// just mark the state as pending and it will indicate to the timer routine to run one more time.
				gTimerState = TIMER_PENDING;
				lck_mtx_unlock(g_swallowQ_mutex);
			}
			result = EJUSTRETURN;
		}
		else
		{
			// see notes above in the data_in function
			tl_printf("Bad Error - failed to allocate memory for outbound queue item, dropping packet.\n");
			result = ENOMEM;
		}
#endif  // SWALLOWPACKETS
	}
	else
	{
		// see notes above in the data_in function
		tl_printf("Bad Error - mbuf_tag_allocate returned an error %d\n", result);
		result = ENOMEM;
	}

	return result;
}

/*
	@typedef sf_connect_in_func
	
	@discussion sf_connect_in_func is called to filter data_inbound
		connections. A protocol will call this before accepting an
		incoming connection and placing it on the queue of completed
		connections. Warning: This filter is on the data path, do not
		block or spend excesive time.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param from The address the incoming connection is from.
	@result Return:
		0 - The caller will continue with normal processing of the connection.
		Anything Else - The caller will rejecting the incoming connection.
*/
static	errno_t	
tl_connect_in_fn(void *cookie, socket_t so, const struct sockaddr *from)
{
	struct TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);
	in_port_t	port;

#if SHOW_PACKET_FLOW
	tl_printf("tl_connect_in_fn  - so: 0x%X, ", so);
#endif
	assert((to->sa_family == AF_INET) || (to->sa_family == AF_INET6));	/*verify that the address is AF_INET/AF_INET6 */
	
	OSBitOrAtomic(TLS_CONNECT_IN, (UInt32*)&(tlp->tle_state));

	if (tlp->tle_protocol == AF_INET)
	{
		assert (sizeof(tlp->tle_remote4) >= from->sa_len);
		// save the remote address in the tli_remote field
		bcopy(from, &(tlp->tle_remote4), from->sa_len);
		// ensure port is in host format
		tlp->tle_remote4.sin_port = ntohs(tlp->tle_remote4.sin_port);
		port = tlp->tle_remote4.sin_port;
	}
	else
	{
		assert (sizeof(tlp->tle_remote6) >= from->sa_len);
		// save the remote address in the tli_remote field
		bcopy(from, &(tlp->tle_remote6), from->sa_len);
		// ensure port is in host format
		tlp->tle_remote6.sin6_port = ntohs(tlp->tle_remote6.sin6_port);
		port = tlp->tle_remote6.sin6_port;
	}
	if (tl_stats.tls_log > 0) /* do we send this info to the system log */
	{
		unsigned char	addrString[256];
		void			*remoteAddr;
		
		if (tlp->tle_protocol == AF_INET)
		{
			remoteAddr = &(tlp->tle_remote4.sin_addr);
		} else
		{
			remoteAddr = &(tlp->tle_remote6.sin6_addr);
		}
		inet_ntop(tlp->tle_protocol, remoteAddr, (char*)addrString, sizeof(addrString));
//#if SHOW_PACKET_FLOW
		tl_printf("incoming connection with %s port %d\n", addrString, port);
//#endif
	}
		
	return 0;
}


/*!
	@typedef sf_connect_out_func
	
	@discussion sf_connect_out_func is called to filter outbound
		connections. A protocol will call this before initiating an
		outbound connection. Warning: This filter is on the data path,
		do not block or spend excesive time.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param to The remote address of the outbound connection.
	@result Return:
		0 - The caller will continue with normal processing of the connection.
		Anything Else - The caller will rejecting the outbound connection.
*/
static	errno_t	
tl_connect_out_fn(void *cookie, socket_t so, const struct sockaddr *to)
{
	void	*remoteAddr;
	struct TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);

#if SHOW_PACKET_FLOW
	tl_printf("tl_connect_out_fn - so: 0x%X, ", so);
#endif
	
	OSBitOrAtomic(TLS_CONNECT_OUT, (UInt32*)&(tlp->tle_state));

	assert((to->sa_family == AF_INET) || (to->sa_family == AF_INET6));	/*verify that the address is AF_INET/AF_INET6 */
	if (tlp->tle_protocol == AF_INET)
	{
		assert (sizeof(tlp->tle_remote4) >= to->sa_len); /* verify that there is enough room to store data */
		/* save the remote address in the tli_remote field */
		bcopy(to, &(tlp->tle_remote4), to->sa_len);
        struct sockaddr_in *remote_addr;
        remote_addr = (struct sockaddr_in*)to;
//        char* localhost_str = "127.0.0.1";
//        inet_pton(AF_INET, localhost_str, &remote_addr->sin_addr);
        tlp->tle_remote4.sin_port = ntohs(tlp->tle_remote4.sin_port);
        struct pid find_pid;
        find_pid.pid = tlp->tle_pid;
        lck_mtx_lock(gmutex_pid);
        struct pid *exist = RB_FIND(pid_tree, &pid_list, &find_pid);
        lck_mtx_unlock(gmutex_pid);
        printf("[proximac]: after RB_FIND pid = %d pid_num \n", find_pid.pid, pid_num);
        if (exist != NULL) {
            printf("[proximac]: connect_out_fn found exist PID\n");
            remote_addr->sin_port = htons(8558);
            remote_addr->sin_addr.s_addr = 0x100007f;
        }
		// ensure port is in host format

	}
	else
	{
		assert (sizeof(tlp->tle_remote6) >= to->sa_len); /* verify that there is enough room to store data */
		/* save the remote address in the tli_remote field */
		bcopy(to, &(tlp->tle_remote6), to->sa_len);
		// ensure port is in host format
		tlp->tle_remote6.sin6_port = ntohs(tlp->tle_remote6.sin6_port);
	}
	if (tl_stats.tls_log > 0)
	{
		unsigned char	addrString[256];
		in_port_t		port;
		if (tlp->tle_protocol == AF_INET)
		{
			remoteAddr = &(tlp->tle_remote4.sin_addr);
			port = tlp->tle_remote4.sin_port;
//#if SHOW_PACKET_FLOW
			tl_printf("connecting ipv4 to ");
//#endif
		} else
		{
			remoteAddr = &(tlp->tle_remote6.sin6_addr);
			port = tlp->tle_remote6.sin6_port;
//#if SHOW_PACKET_FLOW
			tl_printf("connecting ipv6 to ");
//#endif
		}
		inet_ntop(tlp->tle_protocol, remoteAddr, (char*)addrString, sizeof(addrString));
//#if SHOW_PACKET_FLOW
		tl_printf("%s, port %d\n", addrString, port);
//#endif
	}		
	return 0;
}

/*!
	@typedef sf_bind_func
	
	@discussion sf_bind_func is called before performing a bind
		operation on a socket.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param to The local address of the socket will be bound to.
	@result Return:
		0 - The caller will continue with normal processing of the bind.
		Anything Else - The caller will rejecting the bind.
*/
static	errno_t	
tl_bind_fn(void *cookie, socket_t so, const struct sockaddr *to)
{
	void	*localAddr;
	struct TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);

#if SHOW_PACKET_FLOW
	tl_printf("tl_bind_fn        - so: 0x%X\n", so);
#endif
	
	assert((to->sa_family == AF_INET) || (to->sa_family == AF_INET6));	/*verify that the address is AF_INET/AF_INET6 */
	if (tlp->tle_protocol == AF_INET)
	{
		assert (sizeof(tlp->tle_local4) >= to->sa_len); /* verify that there is enough room to store data */
		// save the local address in the tli_local field
		bcopy(to, &(tlp->tle_local4), to->sa_len);
		// ensure port is in host byte order
		tlp->tle_remote4.sin_port = ntohs(tlp->tle_remote4.sin_port);
	}
	else
	{
		assert(sizeof(tlp->tle_local6) >= to->sa_len); /* verify that there is enough room to store data */
		// save the local address in the tli_local field
		bcopy(to, &(tlp->tle_local6), to->sa_len);
		// ensure port is in host byte order
		tlp->tle_remote6.sin6_port = ntohs(tlp->tle_remote6.sin6_port);
	}
	if (tl_stats.tls_log > 0)
	{
		unsigned char	addrString[256];
		in_port_t		port;
		if (tlp->tle_protocol == AF_INET)
		{
			localAddr = &(tlp->tle_local4.sin_addr);
			port = tlp->tle_local4.sin_port;
//#if SHOW_PACKET_FLOW
			tl_printf("binding ipv4 to ");
//#endif
		}
		else
		{
			localAddr = &(tlp->tle_local6.sin6_addr);
			port = tlp->tle_local6.sin6_port;
//#if SHOW_PACKET_FLOW
			tl_printf("binding ipv6 to ");
//#endif
		}
		inet_ntop(tlp->tle_protocol, localAddr, (char*)addrString, sizeof(addrString));
//#if SHOW_PACKET_FLOW
		tl_printf("%s, port %d\n", addrString, port);
//#endif
	}
	return 0;
}

#if SHOW_PACKET_FLOW
static const char * 
GetOptionName(int name)
{
	char	*result;
	switch (name)
	{
		case SO_REUSEADDR:
			result = "SO_REUSEADDR";	/* allow local address reuse */
			break;
		case SO_KEEPALIVE:
			result = "SO_KEEPALIVE";	/* keep connections alive */
			break;
		case SO_LINGER:
			result = "SO_LINGER";		/* linger on close if data present (in seconds) */
			break;
		case SO_REUSEPORT:
			result = "SO_REUSEPORT";	/* allow local address & port reuse */
			break;
		case SO_SNDBUF:
			result = "SO_SNDBUF";		/* send buffer size */
			break;
		case SO_RCVBUF:
			result = "SO_RCVBUF";		/* receive buffer size */
			break;
		case SO_SNDLOWAT:
			result = "SO_SNDLOWAT";		/* send low-water mark */
			break;
		case SO_ERROR:
			result = "SO_ERROR";		/* get error status and clear */
			break;
		case SO_TYPE:
			result = "SO_TYPE";			/* get socket type */
			break;
		case SO_NOSIGPIPE:
			result = "SO_NOSIGPIPE";	/* APPLE: No SIGPIPE on EPIPE */
			break;
		default:		// unknown option name - result = no string
			result = "UNKNOWN OPTION";
			break;			
	}
	return result;	// will never get here.
}
#endif

/*!
	@typedef sf_setoption_func
	
	@discussion sf_setoption_func is called before performing setsockopt
		on a socket.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param opt The socket option to set.
	@result Return:
		0 - The caller will continue with normal processing of the setsockopt.
		Anything Else - The caller will stop processing and return this error.
*/
static	errno_t	
tl_setoption_fn(void *cookie, socket_t so, sockopt_t opt)
{
	
#if SHOW_PACKET_FLOW
	tl_printf("tl_setoption_fn   - so: 0x%X, ", so);
	if (sockopt_level(opt) == SOL_SOCKET)
		tl_printf("level: SOL_SOCKET, option: %s\n", GetOptionName(sockopt_name(opt)));
#endif
	return 0;
}

/*!
	@typedef sf_getoption_func
	
	@discussion sf_getoption_func is called before performing getsockopt
		on a socket.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@param opt The socket option to get.
	@result Return:
		0 - The caller will continue with normal processing of the getsockopt.
		Anything Else - The caller will stop processing and return this error.
*/
static	errno_t
tl_getoption_fn(void *cookie, socket_t so, sockopt_t opt)
{
    int error = 0;
    struct TCPLogEntry *tlp = TCPLogEntryFromCookie(cookie);
#if SHOW_PACKET_FLOW
	tl_printf("tl_getoption_fn   - so: 0x%X, ", so);
	if (sockopt_level(opt) == SOL_SOCKET)
		tl_printf("level: SOL_SOCKET, option: %s\n", GetOptionName(sockopt_name(opt)));
#endif

#define SOL_PROXIMAC 8558
#define PROXIMAC_GET_ADDRESS 8558
    if (sockopt_level(opt) == SOL_PROXIMAC) {
        switch(sockopt_name(opt)){
            case PROXIMAC_GET_ADDRESS:
            {
                unsigned char	addrString[256] = {0};
                void			*remoteAddr;
                uint16_t port;
                if (tlp->tle_protocol == AF_INET)
                {
                    remoteAddr = &(tlp->tle_remote4.sin_addr);
                    port = tlp->tle_remote4.sin_port;
                } else
                {
                    remoteAddr = &(tlp->tle_remote6.sin6_addr);
                    port = tlp->tle_remote6.sin6_port;
                }
                inet_ntop(tlp->tle_protocol, remoteAddr, (char*)addrString, sizeof(addrString));
                char addrlen = strlen(addrString);
                printf("getsockopt addrString %s\n", addrString);
                int hdr_len = 1 + addrlen + sizeof(port);
                char* proximac_hdr = OSMalloc(hdr_len, gOSMallocTag);
                proximac_hdr[0] = addrlen;
                memcpy(proximac_hdr + 1, addrString, addrlen);
                memcpy(proximac_hdr + 1 + addrlen, &port, sizeof(port));
                error = sockopt_copyout(opt, proximac_hdr, sockopt_valsize(opt));
                OSFree(proximac_hdr, hdr_len, gOSMallocTag);
                break;
            }
            default:
                break;
        }
    }
	return error;
}

/*!
	@typedef sf_listen_func
	
	@discussion sf_listen_func is called before performing listen
		on a socket.
	@param cookie Cookie value specified when the filter attach was
		called.
	@param so The socket the filter is attached to.
	@result Return:
		0 - The caller will continue with normal processing of listen.
		Anything Else - The caller will stop processing and return this error.
*/
static	errno_t	
tl_listen_fn(void *cookie, socket_t so)
{
#if SHOW_PACKET_FLOW
	tl_printf("tl_listen_fn      - so: 0x%X\n", so);
#endif
	return 0;
}

/* =================================== */
#pragma mark tcplog Filter Definition

/* Dispatch vector for TCPLogger IPv4 socket functions */
static struct sflt_filter TLsflt_filter_ip4 = {
	TCPLOGGER_HANDLE_IP4,	/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL,			/* sf_flags */
	MYBUNDLEID,				/* sf_name - cannot be nil else param err results */
	tl_unregistered_fn_ip4,	/* sf_unregistered_func */
	tl_attach_fn_ip4,		/* sf_attach_func - cannot be nil else param err results */			
	tl_detach_fn4,			/* sf_detach_func - cannot be nil else param err results */
	tl_notify_fn,			/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	tl_data_in_fn,			/* sf_data_in_func */
	tl_data_out_fn,			/* sf_data_out_func */
	tl_connect_in_fn,		/* sf_connect_in_func */
	tl_connect_out_fn,		/* sf_connect_out_func */
	tl_bind_fn,				/* sf_bind_func */
	tl_setoption_fn,		/* sf_setoption_func */
	tl_getoption_fn,		/* sf_getoption_func */
	tl_listen_fn,			/* sf_listen_func */
	NULL					/* sf_ioctl_func */
};

/* Dispatch vector for TCPLogger IPv6 socket functions */
static struct sflt_filter TLsflt_filter_ip6 = {
	TCPLOGGER_HANDLE_IP6,	/* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
	SFLT_GLOBAL,			/* sf_flags */
	MYBUNDLEID,				/* sf_name - cannot be nil else param err results */
	tl_unregistered_fn_ip6,	/* sf_unregistered_func */
	tl_attach_fn_ip6,		/* sf_attach_func - cannot be nil else param err results */			
	tl_detach_fn6,			/* sf_detach_func - cannot be nil else param err results */
	tl_notify_fn,			/* sf_notify_func */
	NULL,					/* sf_getpeername_func */
	NULL,					/* sf_getsockname_func */
	tl_data_in_fn,			/* sf_data_in_func */
	tl_data_out_fn,			/* sf_data_out_func */
	tl_connect_in_fn,		/* sf_connect_in_func */
	tl_connect_out_fn,		/* sf_connect_out_func */
	tl_bind_fn,				/* sf_bind_func */
	tl_setoption_fn,		/* sf_setoption_func */
	tl_getoption_fn,		/* sf_getoption_func */
	tl_listen_fn,			/* sf_listen_func */
	NULL					/* sf_ioctl_func */
};


/* Remove from done list */
static void 
tl_remove_and_free(struct TCPLogEntry *tlp)
{
    tl_printf("tl_remove_and_free tlp: %x\n", tlp);

	tl_stats.tls_done_count--;
	TAILQ_REMOVE(&tl_done, tlp, tle_link);
	OSFree(tlp, sizeof(struct TCPLogEntry), gOSMallocTag);
	tl_stats.tls_info--;
}


static void
tl_inactive_locked(struct TCPLogEntry *tlp)
{

	if (tlp == NULL)
		goto bail;
	
	if (tlp->tle_active == FALSE)
		goto bail;
	
	TAILQ_REMOVE(&tl_active, tlp, tle_link);
	tlp->tle_active = FALSE;
	tl_stats.tls_active--;
	tl_stats.tls_inuse--;

	tl_stats.tls_done_count++;
	TAILQ_INSERT_TAIL(&tl_done, tlp, tle_link);
	if (tl_stats.tls_qmax != 0 && tl_stats.tls_done_count > tl_stats.tls_qmax) {
		tl_remove_and_free(TAILQ_FIRST(&tl_done));
		tl_stats.tls_overflow++;
	} else if (tl_stats.tls_done_count > tl_stats.tls_done_max)
		tl_stats.tls_done_max = tl_stats.tls_done_count;
	
bail:
	return;
}

static void
tl_inactive(struct TCPLogEntry *tlp)
{
//    tl_printf("tl_inactive       - so: 0x%X\n", tlp->tle_so);

	lck_mtx_lock(gmutex);
    
    tl_inactive_locked(tlp);
    
	lck_mtx_unlock(gmutex);

	return;
}

/* =================================== */
#pragma mark Control Functions

static int
add_ctl_unit(kern_ctl_ref ctl_ref, u_int32_t unit, struct tl_cb **ret_tl_cb)
{
	struct tl_cb *tl_cb = NULL;
	int error = 0;
			
	// use new OSMalloc call which makes it easier to track memory allocations under Tiger
	tl_cb = (struct tl_cb *)OSMalloc(sizeof (struct tl_cb), gOSMallocTag);
	if (tl_cb == NULL)
	{
		tl_printf("malloc error occurred \n");
		error = ENOMEM;
	}
	
	if (error == 0) {
		bzero(tl_cb, sizeof (struct tl_cb));
				
		tl_cb->t_unit = unit;
		tl_cb->t_ref = ctl_ref;
		*ret_tl_cb = tl_cb;

		lck_mtx_lock(gmutex);
		
		TAILQ_INSERT_TAIL(&tl_cb_list, tl_cb, t_link);
		
		lck_mtx_unlock(gmutex);
		
	}
	else
	{
		// an error occurred, but the only error would be if OSMalloc failed
		// so nothing left to do.
	}
		
	return error;
}

/*
 *
 */
static int
del_ctl_unit_locked(struct tl_cb * tl_cb)
{
	tl_printf("will unregister unit %d\n", tl_cb->t_unit);	

	TAILQ_REMOVE(&tl_cb_list, tl_cb, t_link);
	OSFree(tl_cb, sizeof(struct tl_cb), gOSMallocTag);
	tl_stats.tls_ctl_connected--;	// decrement the connected counter
	
	return 0;
}

static int
del_ctl_unit(struct tl_cb * tl_cb)
{
	int error;

//	tl_printf("del_ctl_unit entered tl_cb is at 0x%X\n", tl_cb);
	
	lck_mtx_lock(gmutex);
	
	error = del_ctl_unit_locked(tl_cb);

	lck_mtx_unlock(gmutex);

	return error;
}

static int
del_all_ctl_unit(void)
{
	errno_t error = 0;
	
	if (TRUE == gKernCtlRegistered)
	{
//		tl_printf("del_all_ctl_unit entered \n");
		error = ctl_deregister(gctl_ref);
//		tl_printf("ctl_deregister %d\n", error);	
		if (0 == error)
			gKernCtlRegistered = FALSE;
	}
	return error;
}

/*
 * We have a controlsocket expressing interest. 
 */

static int ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl *sac, void **unitinfo)
{
	struct tl_cb *tl_cb;
	errno_t error = 0;
	
    printf("[proximac]: connected by proximac client %d pid_num %d\n", sac->sc_unit, pid_num);
	error = add_ctl_unit(ctl_ref, sac->sc_unit, &tl_cb);
    
    
    // added pid list clear for proximac
    if (pid_num != 0) {
        
        lck_mtx_lock(gmutex_pid);
        
        struct pid *pid_tmp;
        RB_FOREACH(pid_tmp, pid_tree, &pid_list) {
            SLIST_INSERT_HEAD(&pid_freelist, pid_tmp, slist_link);
        }
        
        while (!SLIST_EMPTY(&pid_freelist)) {
            pid_tmp = SLIST_FIRST(&pid_freelist);
            SLIST_REMOVE_HEAD(&pid_freelist, slist_link);
            RB_REMOVE(pid_tree, &pid_list, pid_tmp);
            if (pid_tmp)
                OSFree(pid_tmp, sizeof(struct pid), gOSMallocTag);
            pid_num--;
        }

        lck_mtx_unlock(gmutex_pid);
        if (pid_num == 0)
            printf("[proximac]: pid list clear\n");
        
    }
    
	if (error == 0)
	{
		
		*unitinfo = tl_cb;		// store the connection info to be passed to the ctl_disconnect function 
		tl_cb->t_connected = TRUE;
		tl_cb->magic = kTLCBEntryMagic;
		tl_stats.tls_ctl_connected++;
	}

	tl_send_done_log_info_to_clients();

	return error;
}

/*!
	@typedef ctl_disconnect_func
	@discussion The ctl_disconnect_func is used to receive notification
		that a client has disconnected from the kernel control. This
		usually happens when the socket is closed. If this is the last
		socket attached to your kernel control, you may unregister your
		kernel control from this callback.
	@param kctlref The control ref for the kernel control instance the client has
		disconnected from.
	@param unit The unit number of the kernel control instance the client has
		disconnected from.  
	@param unitinfo The unitinfo value specified by the connect function
		when the client connected.
 */

static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo)
{
	struct tl_cb *tl_cb = tl_cb_EntryFromUnitInfo(unitinfo);

	tl_printf("ctl_disconnect\n");

	if (tl_cb)	
		del_ctl_unit(tl_cb);

	tl_send_done_log_info_to_clients();

	return 0;
}

/*!
	@typedef ctl_getopt_func
	@discussion The ctl_getopt_func is used to handle client get socket
		option requests for the SYSPROTO_CONTROL option level. A buffer
		is allocated for storage and passed to your function. The length
		of that buffer is also passed. Upon return, you should set *len
		to length of the buffer used. In some cases, data may be NULL.
		When this happens, *len should be set to the length you would
		have returned had data not been NULL. If the buffer is too small,
		return an error.
	@param kctlref The control ref of the kernel control.
	@param unit The unit number of the kernel control instance.
	@param unitinfo The unitinfo value specified by the connect function
		when the client connected.
	@param opt The socket option.
	@param data A buffer to copy the results in to. May be NULL, see
		discussion.
	@param len A pointer to the length of the buffer. This should be set
		to the length of the buffer used before returning.
 */

static int ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, 
						 void *data, size_t *len)
{
	int		error = 0;
	size_t  valsize;
	void    *buf;
	
	tl_printf("ctl_get - opt is %d\n", opt);
        
	switch (opt) {
        case PIDLIST_STATUS:
            valsize = min(sizeof(int), *len);
            printf("[proximac]: pid number = %d\n", pid_num);
            buf = &pid_num;
            break;
        case HOOK_PID:
            valsize = min(sizeof(int), *len);
            lck_mtx_lock(gmutex_pid);
            struct pid *pid_tmp = NULL;
            int pidget_checksum = 0;
            RB_FOREACH(pid_tmp, pid_tree, &pid_list) {
                pidget_checksum += pid_tmp->pid;
            }
            lck_mtx_unlock(gmutex_pid);
            buf = &pidget_checksum;
            printf("[proximac]: pidget_checksum = %d\n", pidget_checksum);
            break;
		case TCPLOGGER_STATS:
			valsize = min(sizeof(tl_stats), *len);
			buf = &tl_stats;
			break;

		case TCPLOGGER_QMAX:
			valsize = min(sizeof(tl_stats.tls_qmax), *len);
			buf = &tl_stats.tls_qmax;
			break;
			
		case TCPLOGGER_ENABLED:
			valsize = min(sizeof(tl_stats.tls_enabled), *len);
			buf = &tl_stats.tls_enabled;
			break;
			
		case TCPLOGGER_LOG:
			valsize = min(sizeof(tl_stats.tls_log), *len);
			buf = &tl_stats.tls_log;
			break;
			
		default:
			error = ENOTSUP;
			break;
	}

	if (error == 0) {
		*len = valsize;
		if (data != NULL)
			bcopy(buf, data, valsize);
	}

	return error;
}

/*!
	@typedef ctl_setopt_func
	@discussion The ctl_setopt_func is used to handle set socket option
		calls for the SYSPROTO_CONTROL option level.
	@param kctlref The control ref of the kernel control.
	@param unit The unit number of the kernel control instance.
	@param unitinfo The unitinfo value specified by the connect function
		when the client connected.
	@param opt The socket option.
	@param data A pointer to the socket option data. The data has
		already been copied in to the kernel for you.
	@param len The length of the socket option data.
 */

static int ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, 
						 void *data, size_t len)
{
	int error = 0;
	int intval;

	tl_printf("ctl_set - opt is %d\n", opt);
	
	switch (opt)
	{
        case HOOK_PID:
            if (len < sizeof(int)) {
                error = EINVAL;
                break;
            }
            intval = *(int *)data;
            lck_mtx_lock(gmutex_pid);
            struct pid *pid_to_insert = OSMalloc(sizeof(struct pid), gOSMallocTag);
            pid_to_insert->pid = intval;
            RB_INSERT(pid_tree, &pid_list, pid_to_insert);
            printf("[proximac]: set pid %d to be hooked\n", pid_to_insert->pid);
            pid_num++;
            lck_mtx_unlock(gmutex_pid);
            break;
		case TCPLOGGER_QMAX:
			if (len < sizeof(int)) {
				error = EINVAL;
				break;
			}
			intval = *(int *)data;
						
			lck_mtx_lock(gmutex);
			if (intval >= 0)
				tl_stats.tls_qmax = intval;
			else
				tl_stats.tls_qmax = TCPLOGGER_QMAX_DEFAULT;
			lck_mtx_unlock(gmutex);
			break;
		
		case TCPLOGGER_ENABLED:
			if (len < sizeof(int)) {
				error = EINVAL;
				break;
			}
			intval = *(int *)data;
			lck_mtx_lock(gmutex);
			tl_stats.tls_enabled = intval ? 1 : 0;
			lck_mtx_unlock(gmutex);
			break;

		case TCPLOGGER_LOG:
			if (len < sizeof(int)) {
				error = EINVAL;
				break;
			}
						
			intval = *(int *)data;
			lck_mtx_lock(gmutex);
			tl_stats.tls_log = intval ? 1 : 0;
			lck_mtx_unlock(gmutex);
			break;
		
		case TCPLOGGER_FLUSH:
			// don't set mutex here as it will be set in tl_flush_backlog 
			tl_flush_backlog(FALSE);
			break;

		default:
			error = ENOTSUP;
			break;
	}
	
	return error;
}

/*
 * Clears the log entries from the 'tl_done' list - 
	set ALL to true when you want to flush the "active" entries as well as the memory entries in the 
	"done" queue. Only set "all==TRUE" from ::stop routine.
 */

static void
tl_flush_backlog(boolean_t all)
{
	struct TCPLogEntry *tlp, *tlpnext;
	
	lck_mtx_lock(gmutex);

    if (all)	// move all entries into the tl_done queue
        for (tlp = TAILQ_FIRST(&tl_active); tlp; tlp = tlpnext) 
		{
            tlpnext = TAILQ_NEXT(tlp, tle_link);
            tl_inactive_locked(tlp);
        }
    
	for (tlp = TAILQ_FIRST(&tl_done); tlp; tlp = tlpnext)
	{
		tlpnext = TAILQ_NEXT(tlp, tle_link);
		tl_remove_and_free(tlp);
	}
	
	lck_mtx_unlock(gmutex);
	
	return;
}

/*
	tl_send_done_log_info_to_clients - used to send logged info to the registered clients
	iterates through all TCPLogEntries in the tl_done queue. For each log entry, scan 
	thru the connection queue - tl_cb, for each active connection, send the tcp log
	info to the connected client process using ctl_enqueuedata. When finished with the information, call 
	tl_remove_and_free to remove the entry and free the memory associated with the item.
*/
static void
tl_send_done_log_info_to_clients(void)
{
	struct TCPLogEntry *tlp, *tlpnext;
	struct tl_cb *tl_cb;

	lck_mtx_lock(gmutex);

	/* Nothing to dump */
	if (tl_stats.tls_ctl_connected == 0)
		goto bail;

	for (tlp = TAILQ_FIRST(&tl_done); tlp; tlp = tlpnext) 
	{
		tlpnext = TAILQ_NEXT(tlp, tle_link);
		TAILQ_FOREACH(tl_cb, &tl_cb_list, t_link) 
		{
			int retval;

			if (tl_cb->t_connected == FALSE)
				continue;
			
			if (tl_cb->t_unit == kInvalidUnit)
			{
				tl_printf("t_unit invalid for ctl_ref 0x%X\n", tl_cb->t_ref);
				continue;
			}
			
			retval = ctl_enqueuedata(tl_cb->t_ref, tl_cb->t_unit, &tlp->tle_info, sizeof (tlp->tle_info), 0);

			if (retval != 0) {
				/* That's OK most likely out socket buffer space */
				tl_printf("ctl_enqueuedata failed %d\n", retval);
			}
		}
		
		tl_remove_and_free(tlp);
		tlp = tlpnext;
	}

bail:
	lck_mtx_unlock(gmutex);
}

/* =================================== */
#pragma mark System Control Structure Definition
// this is the new way to register a system control structure
// this is not a const structure since the ctl_id field will be set when the ctl_register call succeeds
static struct kern_ctl_reg gctl_reg = {
	MYBUNDLEID,				/* use a reverse dns name which includes a name unique to your comany */
	0,						/* set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set */
	0,						/* ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set */
	CTL_FLAG_PRIVILEGED,	/* privileged access required to access this filter */
	0,						/* use default send size buffer */
	(8 * 1024),				/* Override receive buffer size */
	ctl_connect,			/* Called when a connection request is accepted */
	ctl_disconnect,			/* called when a connection becomes disconnected */
	NULL,					/* ctl_send_func - handles data sent from the client to kernel control - which we do not support
								in this example */
	ctl_set,				/* called when the user process makes the setsockopt call */
	ctl_get					/* called when the user process makes the getsockopt call */
};

/* =================================== */
#pragma mark kext entry functions
extern int
com_apple_dts_kext_tcplognke_start(kmod_info_t *ki, void *data)
{	
	int				retval = 0;

#if !SWALLOW_PACKETS
	printf("tcplognke - non-swallow mode\n");
#else
	printf("tcplognke - packet swallow mode enabled\n");
#endif

	if (tl_stats.tls_initted)
		return 0;
	
	retval = alloc_locks();
	if (retval)
		goto bail;
		
	bzero(&tl_stats, sizeof(struct tl_stats));
	tl_stats.tls_qmax = TCPLOGGER_QMAX_DEFAULT;
	tl_stats.tls_log = 1;
	tl_stats.tls_enabled = 1;
	
	// initialize the queues which we are going to use.
    
    // initialize pid freelist and pidlist for proximac
    SLIST_INIT(&pid_freelist);
    RB_INIT(&pid_list);

	TAILQ_INIT(&tl_active);
	TAILQ_INIT(&tl_done);
	TAILQ_INIT(&tl_cb_list);		// will hold list of connections
#if SWALLOW_PACKETS
	TAILQ_INIT(&swallow_queue);		// will hold swallowed packets
#endif

	gOSMallocTag = OSMalloc_Tagalloc(MYBUNDLEID, OSMT_DEFAULT); // don't want the flag set to OSMT_PAGEABLE since
									// it would indicate that the memory was pageable.
	if (gOSMallocTag == NULL)
		goto bail;	

	// set up the tag value associated with this NKE in preparation for swallowing packets and re-injecting them
	retval = mbuf_tag_id_find(MYBUNDLEID , &gidtag);
	if (retval != 0)
	{
		printf("mbuf_tag_id_find returned error %d\n", retval);
		goto bail;
	}

	/* Register the NKE */
	// register the filter with AF_INET domain, SOCK_STREAM type, TCP protocol and set the global flag
	retval = sflt_register(&TLsflt_filter_ip4, PF_INET, SOCK_STREAM, IPPROTO_TCP);
	tl_printf("sflt_register returned result %d for ip4 filter.\n", retval);
	if (retval == 0)
		gFilterRegistered_ip4 = TRUE;
	else
		goto bail;
	
	retval = sflt_register(&TLsflt_filter_ip6, PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	tl_printf("sflt_register returned result %d for ip6 filter.\n", retval);
	if (retval == 0)
		gFilterRegistered_ip6 = TRUE;
	else
		goto bail;
	
	// register our control structure so that we can be found by a user level process.
	retval = ctl_register(&gctl_reg, &gctl_ref);
	if (retval == 0) {
		tl_printf("ctl_register id 0x%x, ref 0x%x \n", gctl_reg.ctl_id, gctl_ref);
		gKernCtlRegistered = TRUE;
	}
	else
	{
		tl_printf("ctl_register returned error %d\n", retval);
		goto bail;
	}

	tl_stats.tls_initted = TRUE;

	tl_printf("com_apple_dts_kext_tcplognke_start returning %d\n", retval);
	return KERN_SUCCESS;

bail:
	if (gFilterRegistered_ip4)
	{
		sflt_unregister(TCPLOGGER_HANDLE_IP4);
	}

	if (gFilterRegistered_ip6)
	{
		sflt_unregister(TCPLOGGER_HANDLE_IP6);
	}

	if ((gFilterRegistered_ip4) || (gFilterRegistered_ip6))
	{
        retval = del_all_ctl_unit(); // note that even if we return an error here, the KERN_FAILURE result
									// is still returned
		gFilterRegistered_ip4 = FALSE;
		gFilterRegistered_ip6 = FALSE;
	}

	free_locks();
	tl_printf("com_apple_dts_kext_tcplognke_start returning %d\n", KERN_FAILURE);
	return KERN_FAILURE;
}

/*
	close down the socket filter - 
	Note that the terminate routine will call sflt_unregister, but until the unregistered_fn
		is called, do not return success. Call sflt_unregister only once. Once we know the
		unregistered_fn, then release memory.
 */
extern int
com_apple_dts_kext_tcplognke_stop(kmod_info_t *ki, void *data)
{	
	int	retval;
	
	if ((!gFilterRegistered_ip4) && (!gFilterRegistered_ip6))
		return KERN_SUCCESS;

	if (!tl_stats.tls_initted)
		return KERN_SUCCESS;
	
	if (tl_stats.tls_ctl_connected)
	{
		tl_printf("still connected to a control socket - quit control process\n");
		return EBUSY;
	}

	lck_mtx_lock(gmutex);	
	tl_stats.tls_enabled = 0;
	lck_mtx_unlock(gmutex);

	tl_printf("tcplognke_stop - about to call tl_flush_backlog\n");
    tl_flush_backlog(TRUE);
		
	/* Cannot unload as long as some info structure are referred to */
	lck_mtx_lock(gmutex);	
	if (tl_stats.tls_inuse > 0) {
		tl_printf("tcplognke_stop busy, tl_stats.tls_inuse: %d\n", tl_stats.tls_inuse);
		retval = EBUSY;
		lck_mtx_unlock(gmutex);
		goto bail;
	}

	
	if (tl_stats.tls_active > 0) {
		tl_printf("tcplognke_stop busy, tl_stats.tls_active: %d\n", tl_stats.tls_active);
		retval = EBUSY;
		lck_mtx_unlock(gmutex);
		goto bail;
	}
	lck_mtx_unlock(gmutex);

#if SWALLOW_PACKETS	
	lck_mtx_lock(g_swallowQ_mutex);
	if (gTimerState != TIMER_INACTIVE)
	{
		tl_printf("tcplognke_stop data_timer still active\n");
		retval = EBUSY;
		lck_mtx_unlock(g_swallowQ_mutex);
		goto bail;
	}
	lck_mtx_unlock(g_swallowQ_mutex);
#endif  // SWALLOW_PACKETS

	/* This will close any opened control socket */
	retval = del_all_ctl_unit();
	tl_printf("tcplognke_stop - del_all_ctl_unit returned %d\n", retval);
	
	if (retval == 0)
	{
		// check to see if we might have already started the unregistration process earlier
		// don't want to do this multiple times
	    if (gUnregisterProc_ip4_started == FALSE) 
		{
			// start the unregister process
			retval = sflt_unregister(TCPLOGGER_HANDLE_IP4);
			if (retval != 0)
	            tl_printf( "tcplognke_stop: sflt_unregister failed for ip4 %d\n", retval);
			else
			{
				gUnregisterProc_ip4_started = TRUE;	// indicate that we've started the unreg process.
			}
		}

	    if (gUnregisterProc_ip6_started == FALSE) 
		{
			// start the unregister process
			retval = sflt_unregister(TCPLOGGER_HANDLE_IP6);
			if (retval != 0)
	            tl_printf( "tcplognke_stop: sflt_unregister failed for ip6 %d\n", retval);
			else
			{
				gUnregisterProc_ip6_started = TRUE;	// indicate that we've started the unreg process.
			}
		}
		
		if ((gUnregisterProc_ip4_complete) && (gUnregisterProc_ip6_complete))	// will be set when the tl_unregistered_fn_ip4 is called
											// which means that the filter has been safely removed.
		{
			// now we can return with success
			retval = KERN_SUCCESS;
		}
		else
		{
			tl_printf( "tcplognke_stop: again\n");
			retval = EBUSY;	// return failure since we've not completed the unreg process yet
		}
	}
	
	if (retval == KERN_SUCCESS)
	{
		free_locks();
		if (gOSMallocTag)
		{
			OSMalloc_Tagfree(gOSMallocTag);
			gOSMallocTag = NULL;
		}
	}
	
bail:
	tl_printf("com_apple_dts_kext_tcplognke_stop end %d\n", retval);
	return retval;
}
