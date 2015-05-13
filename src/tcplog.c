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
 * Based on TCPLogger,  a Mac OS X 'global' plug-in
 * used to test out designs for the extensible stack mechanisms for Mac OS X
 *
 * This version uses system domain control sockets, it takes more options, and it
 * displays each TCP connection log entry on a single line
 */

#if !defined(DEBUG)
#define DEBUG	1				// DEBUG == 1 - print logging messsages to system.log
								// DEBUG == 0 - no logging messages.
								/* When DEBUG is enabled, this sample uses the prinff statement from within a
									a signal handle which is not a supported call as per 
									man 2 sigaction.
								*/ 
#endif

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "tcplogger.h"

static int		banner = 40;
static int		gSocket = -1;

static double
tvsub(struct timeval *t1, struct timeval *t0)
{	double elapsed;
	struct timeval tdiff; 

	tdiff.tv_sec = t1->tv_sec - t0->tv_sec;
	tdiff.tv_usec = t1->tv_usec - t0->tv_usec;
	if (tdiff.tv_usec < 0)
		tdiff.tv_sec--, tdiff.tv_usec += 1000000;
	elapsed = tdiff.tv_sec + ((double)tdiff.tv_usec) / 1000000;
	if( elapsed < 0.00001 )  elapsed = 0.00001;
	return(elapsed);
}

static void
TLEPrint(struct TCPLogInfo *tlp)
{   
/*
	const char *ruler =
"123456789x123456789x123456789x123456789x123456789x123456789x123456789x123456789x123456789x123456789x123456789x123456789x";
*/
	const char *normal_banner = 
"       Type   Local Address                  Remote Address                     Ipkts     Ibytes   Opkts     Obytes   uid    pid      duration";
	char		buffer[64];
	const char	*type;
	static int	lines = 0;
	
    if (banner) {
        if ((banner > 0 && (lines % (banner + 1)) == 0) || (banner < 0 && lines == 0))  {
            printf("%s\n", normal_banner);
            lines++;
        }
	}
    if (tlp != 0) {
		
        switch (tlp->tli_state) {
            case TLS_CONNECT_IN:
                type = "INCON ";
                break;
            case TLS_CONNECT_OUT:
                type = "OUTCON";
                break;
            case TLS_LISTENING:
                type = "LISTEN";
                break;
            case 0:
                type = "NONE  ";
                break;
            default:
				printf("state %x\n", tlp->tli_state);
                type = "?     ";
                break;
        }
        printf("%6ld %6s ",
               tlp->tli_genid, type);

		if (tlp->tli_protocol == AF_INET)
		{
			snprintf(buffer, sizeof(buffer), "%s:%d",
				   inet_ntoa(tlp->tli_local.addr4.sin_addr), tlp->tli_local.addr4.sin_port);
			printf("%-30s ", buffer);
			
			snprintf(buffer, sizeof(buffer), "%s:%d",
				   inet_ntoa(tlp->tli_remote.addr4.sin_addr), tlp->tli_remote.addr4.sin_port);
			printf("%-32s ", buffer);
		}
		else
		{
			unsigned char	addrString[256];

			inet_ntop(AF_INET6, &(tlp->tli_local.addr6.sin6_addr), (char*)addrString, sizeof(addrString));
			snprintf(buffer, sizeof(buffer), "%s:%d", addrString, tlp->tli_local.addr6.sin6_port);
			printf("%-30s ", buffer);
				   
			inet_ntop(AF_INET6, &(tlp->tli_remote.addr6.sin6_addr), (char*)addrString, sizeof(addrString));
			snprintf(buffer, sizeof(buffer), "%s:%d", addrString, tlp->tli_remote.addr6.sin6_port);
			printf("%-32s ", buffer);
		}
        
		printf("%7ld %10ld ",
			   (long int)tlp->tli_pkts_in, (long int)tlp->tli_bytes_in);
		printf("%7ld %10ld ",
			  (long int) tlp->tli_pkts_out, (long int)tlp->tli_bytes_out);

        printf("%5d %6d",
               tlp->tli_uid, tlp->tli_pid);
               
        snprintf(buffer, sizeof(buffer), "%6f",
               tvsub(&tlp->tli_stop, &tlp->tli_start));
        printf("  %12s\n", buffer);
        lines++;
    }
	fflush(stdout);
}

static void
test_print()
{
	struct TCPLogInfo tli;
	
	bzero(&tli, sizeof(tli));
	TLEPrint(&tli);
	
	memset(&tli, 127, sizeof(tli));
	TLEPrint(&tli);
	
	return;
}

/*
	SignalHandler - implemented to handle an interrupt from the command line using Ctrl-C.
*/
static void SignalHandler(int sigraised)
{
#if DEBUG
    printf("\ntcplog Interrupted - %d\n", sigraised); // note - printf is unsupported function call from a signal handler
#endif
	if (gSocket > 0);
	{
#if DEBUG
		printf("closing socket %d\n", gSocket);	// note - printf is an unsupported function call from a signal handler
#endif
		close (gSocket);	// per man 2 sigaction, close can be invoked from a signal-catching function.
	}
    
    // exit(0) should not be called from a signal handler.  Use _exit(0) instead
    //
    _exit(0);
}


static void
usage(int help, const char *s)
{
    printf("usage: %s [-m] [-v] [-s] [-q] [-Q max] [-E] [-F]\n", s);
    if (help == 0)
        return;
    printf("tcplog is used to control the tcplognke kernel extension\n");
    printf("The command takes the following options that are evaluated in order, \n");
    printf("and several options may be combined:\n");
    printf(" %-10s%s\n", "-h", "display this help and exit");
    printf(" %-10s%s\n", "-s", "get statistics");
    printf(" %-10s%s\n", "-Q max", "set size of queue for pending log entries");
    printf(" %-10s%s\n", "-q", "get size of queue for pending log entries");
    printf(" %-10s%s\n", "-L n", "set log of tcplognke KEXT on (n > 0) or off (n = 0)");
    printf(" %-10s%s\n", "-E n", "enable log on (n > 0) or off (n = 0)");
    printf(" %-10s%s\n", "-F", "flush pending log entries");
    printf(" %-10s%s\n", "-b n", "use banner once (n < 0), never (n = 0), or every n lines");
    printf(" %-10s%s\n", "-m", "display TCP log entries");
}

int main(int argc, char * const *argv)
{
	struct sockaddr_ctl sc;
	struct TCPLogInfo tlp;
	int n;
	int c;
    int pid_show = 0;
    int pid_set = 0;
    int pid_to_hook = 0;
	int getstats = 0;
	int getqmax = 0;
	int setqmax = 0;
	int monitor = 0;
	struct tl_stats tl_stats;
	socklen_t size;
	int qmax;
	int set_enabled = -1;
	int set_log = -1;
	int flush = 0;
    struct ctl_info ctl_info;
	sig_t	oldHandler;

    // Set up a signal handler so we can clean up when we're interrupted from the command line
    // Otherwise we stay in our run loop forever.
    oldHandler = signal(SIGINT, SignalHandler);
    if (oldHandler == SIG_ERR)
        printf("Could not establish new signal handler");
	
	while ((c = getopt(argc, argv, "k:pmvsqQ:E:FL:xb:h")) != -1) {
		switch(c) {
            case 'k':
                pid_set++;
                pid_to_hook = strtoul(optarg, 0, 0);
                printf("pid_to_hook = %d\n", pid_to_hook);
                break;
            case 'p':
                pid_show++;
                break;
			case 'm':
				monitor++;
				break;
			case 's':
				getstats++;
				break;
			case 'q':
				getqmax++;
				break;
			case 'Q':
				setqmax++;
				qmax = strtoul(optarg, 0, 0);
				break;
			case 'E':
				set_enabled = strtol(optarg, 0, 0);;
				break;
			case 'F':
				flush++;
				break;
			case 'L':
				set_log = strtol(optarg, 0, 0);;
				break;
			case 'x':
				test_print();
				exit(0);
            case 'b':
                banner = strtol(optarg, 0, 0);
                break;
            case 'h':
                usage(1, argv[0]);
				exit(0);
			case '?':
			default:
                usage(0, argv[0]);
				exit(-1);
		}
	}
	
    gSocket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
	if (gSocket < 0) {
		perror("socket SYSPROTO_CONTROL");
		exit(0);
	}
	bzero(&ctl_info, sizeof(struct ctl_info));
	strcpy(ctl_info.ctl_name, MYBUNDLEID);
	if (ioctl(gSocket, CTLIOCGINFO, &ctl_info) == -1) {
		perror("ioctl CTLIOCGINFO");
		exit(0);
	} else
		printf("ctl_id: 0x%x for ctl_name: %s\n", ctl_info.ctl_id, ctl_info.ctl_name);

	bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = SYSPROTO_CONTROL;
	sc.sc_id = ctl_info.ctl_id;
	sc.sc_unit = 0;

	if (connect(gSocket, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl))) {
		perror("connect");
		exit(0);
	}
	
	if (getstats != 0) {
		size = sizeof(tl_stats);
		if (getsockopt(gSocket, SYSPROTO_CONTROL, TCPLOGGER_STATS, &tl_stats, &size) == -1) {
			perror("getsockopt TCPLOGGER_STATS");
			exit(0);
		}
		printf("tls_done_count: %d\n", tl_stats.tls_done_count);
		printf("tls_done_max: %d\n", tl_stats.tls_done_max);
		printf("tls_qmax: %d\n", tl_stats.tls_qmax);
		printf("tls_overflow: %d\n", tl_stats.tls_overflow);
		printf("tls_active: %d\n", tl_stats.tls_active);
		printf("tls_active_max: %d\n", tl_stats.tls_active_max);
		printf("tls_inuse: %d\n", tl_stats.tls_inuse);
		printf("tls_attached: %ld\n", tl_stats.tls_attached);
		printf("tls_freed: %ld\n", tl_stats.tls_freed);
		printf("tls_cannotfree: %ld\n", tl_stats.tls_cannotfree);
		printf("tls_dupfree: %ld\n", tl_stats.tls_dupfree);
		printf("tls_info: %d\n", tl_stats.tls_info);
		printf("tls_ctl_connected: %ld\n", tl_stats.tls_ctl_connected);
		printf("tls_enabled: %d\n", tl_stats.tls_enabled);
		printf("tls_initted: %d\n", tl_stats.tls_initted);
		printf("tls_log: %d\n", tl_stats.tls_log);
	}
	
    if (pid_show != 0) {
        size = sizeof(pid_to_hook);
        if (getsockopt(gSocket, SYSPROTO_CONTROL, HOOK_PID, &pid_to_hook, &size) == -1) {
            perror("getsockopt HOOK_PID");
            exit(0);
        }
        printf("hooked PID: %d\n", pid_to_hook);
    }
    
    if (pid_set != 0) {
        if (setsockopt(gSocket, SYSPROTO_CONTROL, HOOK_PID, &pid_to_hook, sizeof(pid_to_hook)) == -1) {
            printf("setsockopt HOOK_PID %d\n", pid_to_hook);
            exit(0);
        }
    }
    
    if (setqmax != 0) {
		if (setsockopt(gSocket, SYSPROTO_CONTROL, TCPLOGGER_QMAX, &qmax, sizeof(qmax)) == -1) {
			perror("setsockopt TCPLOGGER_QMAX");
			exit(0);
		}
	}
    
	if (getqmax != 0) {
		size = sizeof(qmax);
		if (getsockopt(gSocket, SYSPROTO_CONTROL, TCPLOGGER_QMAX, &qmax, &size) == -1) {
			perror("getsockopt TCPLOGGER_QMAX");
			exit(0);
		}
		printf("qmax: %d\n", qmax);
	}
	
	if (set_log >= 0) {
                printf("TCPLOGGER_LOG called with value %d\n", set_log);
		if (setsockopt(gSocket, SYSPROTO_CONTROL, TCPLOGGER_LOG, &set_log, sizeof(set_log)) == -1) {
			perror("setsockopt TCPLOGGER_LOG");
			exit(0);
        }
	}
	if (set_enabled >= 0) {
		if (setsockopt(gSocket, SYSPROTO_CONTROL, TCPLOGGER_ENABLED, &set_enabled, sizeof(set_enabled)) == -1) {
			perror("setsockopt TCPLOGGER_ENABLED");
			exit(0);
        }
	}
	if (flush > 0) {
		if (setsockopt(gSocket, SYSPROTO_CONTROL, TCPLOGGER_FLUSH, &flush, sizeof(flush)) == -1) {
			perror("getsockopt TCPLOGGER_FLUSH");
			exit(0);
		}
	}
	if (monitor != 0) {

        /* Print the first banner */
        TLEPrint(0);
		/* Now, just read the stuff up! */
		while ((n = recv(gSocket, &tlp, sizeof (tlp), 0)) == sizeof (tlp))
		{
			TLEPrint(&tlp);
		}
	}
	close(gSocket);
	gSocket = -1;
	
	return 0;
}
