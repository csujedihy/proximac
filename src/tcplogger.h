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
	heade file to support the tcplognke netwrok kernel extension.
 */

#ifndef TCPLOGGER_H
#define TCPLOGGER_H

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#define TCPLOGGER_HANDLE_IP4 0xBABABABA		/* Temp hack to identify this filter */
#define TCPLOGGER_HANDLE_IP6 0xABABABAB		/* Temp hack to identify this filter */
						/*
							Used a registered creator type here - to register for one - go to the
							Apple Developer Connection Datatype Registration page
							<http://developer.apple.com/datatype/>
						*/
#define MYBUNDLEID		"com.apple.dts.kext.tcplognke"

/*
	The TCPLogInfo structure is used to pass packet process info from the kext to the
	user land tool - tcplog, on a per connection basis, at the end of a connection.
	The kernel extension passes status information to the tool when the tool is used
	with the -m (display TCP Log entries) option.
*/
struct TCPLogInfo {
	size_t			tli_len;			/* size of structure */
	uint32_t		tli_state;			/* connection state - TLS_CONNECT_OUT or TLS_CONNECT_IN */
	long			tli_genid;			/* one up id for this record */
	union {
		struct sockaddr_in	addr4;		/* ipv4 local addr */
		struct sockaddr_in6	addr6;		/* ipv6 local addr */
	} tli_local;
	union {
		struct sockaddr_in	addr4;		/* ipv4 remote addr */
		struct sockaddr_in6	addr6;		/* ipv6 remote addr */
	} tli_remote;
	uint32_t		tli_bytes_in;
	uint32_t		tli_pkts_in;
	uint32_t		tli_bytes_out;
	uint32_t		tli_pkts_out;
	struct timeval	tli_create;			/* socreate timestamp */
	struct timeval	tli_start;			/* connection complete timestamp */
	struct timeval	tli_stop;			/* connection termination timestamp */
	pid_t			tli_pid;			/* pid that created the socket */
	pid_t			tli_uid;			/* used id that created the socket */
	int				tli_protocol;		/* ipv4 or ipv6 */
};

#define TLS_CONNECT_OUT	0x1	
#define TLS_CONNECT_IN	0x2
#define TLS_LISTENING	0x4
#define TLS_KIND (TLS_CONNECT_OUT | TLS_CONNECT_IN | TLS_LISTENING)

struct tl_stats {
	int tls_done_count;
	int tls_done_max;
	int tls_qmax; /* Maximum number of info structures for be logged */
	int tls_overflow;
	int tls_active;
	int tls_active_max;
	int tls_inuse; /* Currently in use (attached and not free) */
	int tls_info; /* Number of currently allocated info structures */
	long tls_attached;  /* Number of attachment to sockets - used to set one up value of tli_genid */
	long tls_freed;  /* Number of calls to duplicate calls to sofree */
	long tls_cannotfree;  /* Number of calls to duplicate calls to sofree */
	long tls_dupfree;  /* Number of calls to duplicate calls to sofree */
	long tls_ctl_connected; /* Number of control sockets in use */
	int tls_log;
	int tls_enabled;
	boolean_t tls_initted;
};

#define TCPLOGGER_STATS 1   /* get tl_stats*/
#define TCPLOGGER_QMAX  2   /* get or set tls_qmax */
#define TCPLOGGER_ENABLED  3   /* get or set tls_enabled */
#define TCPLOGGER_FLUSH 4
#define TCPLOGGER_ADDUNIT 5
#define TCPLOGGER_DELUNIT 6
#define TCPLOGGER_LOG 7
#define HOOK_PID 8

#endif
