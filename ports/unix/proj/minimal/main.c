/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved. 
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED 
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT 
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING 
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY 
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 * 
 * Author: Adam Dunkels <adam@sics.se>
 * RT timer modifications by Christiaan Simons
 */

#include <unistd.h>
#include <getopt.h>

#include "lwip/init.h"

#include "lwip/debug.h"

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"

#include "lwip/stats.h"

#include "lwip/ip.h"
#include "lwip/ip_frag.h"
#include "lwip/udp.h"
#include "lwip/snmp_msg.h"
#include "lwip/tcp_impl.h"
#include "mintapif.h"
#include "netif/etharp.h"

#include "timer.h"
#include <signal.h>

#include "echo.h"
#include "private_mib.h"

#include "lwip/tcpip.h"
#include "pppmy.h"

/* (manual) host IP configuration */
static ip_addr_t ipaddr, netmask, gw;

/* SNMP trap destination cmd option */
static unsigned char trap_flag;
static ip_addr_t trap_addr;

/* nonstatic debug cmd option, exported in lwipopts.h */
unsigned char debug_flags;

/* 'non-volatile' SNMP settings
  @todo: make these truly non-volatile */
u8_t syscontact_str[255];
u8_t syscontact_len = 0;
u8_t syslocation_str[255];
u8_t syslocation_len = 0;
/* enable == 1, disable == 2 */
u8_t snmpauthentraps_set = 2;

static struct option longopts[] = {
  /* turn on debugging output (if build with LWIP_DEBUG) */
  {"debug", no_argument,        NULL, 'd'},
  /* help */
  {"help", no_argument, NULL, 'h'},
  /* gateway address */
  {"gateway", required_argument, NULL, 'g'},
  /* ip address */
  {"ipaddr", required_argument, NULL, 'i'},
  /* netmask */
  {"netmask", required_argument, NULL, 'm'},
  /* ping destination */
  {"trap_destination", required_argument, NULL, 't'},
  /* new command line options go here! */
  {NULL,   0,                 NULL,  0}
};
#define NUM_OPTS ((sizeof(longopts) / sizeof(struct option)) - 1)

void usage(void)
{
  unsigned char i;
   
  printf("options:\n");
  for (i = 0; i < NUM_OPTS; i++) {
    printf("-%c --%s\n",longopts[i].val, longopts[i].name);
  }
}

/* Callback executed when the TCP/IP init is done. */
static void tcpip_init_done(void *arg)
{
  sys_sem_t sem = (sys_sem_t)arg;

  sys_sem_signal(&sem); /* Signal the waiting thread that the TCP/IP init is done. */
}

void pppLinkStatusCallback(void *ctx, int errCode, void *arg) {
	LWIP_UNUSED_ARG(ctx);

	switch(errCode) {
		case PPPERR_NONE: {             /* No error. */
			struct ppp_addrs *ppp_addrs = arg;
			printf("pppLinkStatusCallback: PPPERR_NONE\n\r");
			printf("   our_ipaddr = %s\n\r", ip_ntoa(&ppp_addrs->our_ipaddr));
			printf("   his_ipaddr = %s\n\r", ip_ntoa(&ppp_addrs->his_ipaddr));
			printf("   netmask    = %s\n\r", ip_ntoa(&ppp_addrs->netmask));
			printf("   dns1       = %s\n\r", ip_ntoa(&ppp_addrs->dns1));
			printf("   dns2       = %s\n\r", ip_ntoa(&ppp_addrs->dns2));
			break;
		}
		case PPPERR_PARAM: {           /* Invalid parameter. */
			printf("pppLinkStatusCallback: PPPERR_PARAM\n\r");
			break;
		}
		case PPPERR_OPEN: {            /* Unable to open PPP session. */
			printf("pppLinkStatusCallback: PPPERR_OPEN\n\r");
			break;
		}
		case PPPERR_DEVICE: {          /* Invalid I/O device for PPP. */
			printf("pppLinkStatusCallback: PPPERR_DEVICE\n\r");
			break;
		}
		case PPPERR_ALLOC: {           /* Unable to allocate resources. */
			printf("pppLinkStatusCallback: PPPERR_ALLOC\n\r");
			break;
		}
		case PPPERR_USER: {            /* User interrupt. */
			printf("pppLinkStatusCallback: PPPERR_USER\n\r");
			break;
		}
		case PPPERR_CONNECT: {         /* Connection lost. */
			printf("pppLinkStatusCallback: PPPERR_CONNECT\n\r");
			break;
		}
		case PPPERR_AUTHFAIL: {        /* Failed authentication challenge. */
			printf("pppLinkStatusCallback: PPPERR_AUTHFAIL\n\r");
			break;
		}
		case PPPERR_PROTOCOL: {        /* Failed to meet protocol. */
			printf("pppLinkStatusCallback: PPPERR_PROTOCOL\n\r");
/*			ppp_desc = pppOverEthernetOpen(&MACB_if, NULL, NULL, pppLinkStatusCallback, NULL);
			printf("ppp_desc = %d\n\r", ppp_desc); */
			break;
		}
		default: {
			printf("pppLinkStatusCallback: unknown errCode %d\n\r", errCode);
			break;
		}
	}

/*	if(errCode != PPPERR_NONE) {
		if(ppp_desc >= 0) {
			//pppOverEthernetClose(ppp_desc);
			ppp_desc = -1;
		}
	} */
}

int
main(int argc, char **argv)
{
  struct netif netif;
  sigset_t mask, oldmask, empty;
  int ch;
  char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};
  sys_sem_t sem;
  char *username = "essai", *password = "aon0viipheehooX";
  int ppp_desc;

  /* startup defaults (may be overridden by one or more opts) */
  IP4_ADDR(&gw, 192,168,0,1);
  IP4_ADDR(&ipaddr, 192,168,0,2);
  IP4_ADDR(&netmask, 255,255,255,0);

  trap_flag = 0;
  /* use debug flags defined by debug.h */
  debug_flags = LWIP_DBG_OFF;

  while ((ch = getopt_long(argc, argv, "dhg:i:m:t:", longopts, NULL)) != -1) {
    switch (ch) {
      case 'd':
        debug_flags |= (LWIP_DBG_ON|LWIP_DBG_TRACE|LWIP_DBG_STATE|LWIP_DBG_FRESH|LWIP_DBG_HALT);
        break;
      case 'h':
        usage();
        exit(0);
        break;
      case 'g':
        ipaddr_aton(optarg, &gw);
        break;
      case 'i':
        ipaddr_aton(optarg, &ipaddr);
        break;
      case 'm':
        ipaddr_aton(optarg, &netmask);
        break;
      case 't':
        trap_flag = !0;
        /* @todo: remove this authentraps tweak 
          when we have proper SET & non-volatile mem */
        snmpauthentraps_set = 1;
        ipaddr_aton(optarg, &trap_addr);
        strncpy(ip_str, ipaddr_ntoa(&trap_addr),sizeof(ip_str));
        printf("SNMP trap destination %s\n", ip_str);
        break;
      default:
        usage();
        break;
    }
  }
  argc -= optind;
  argv += optind;

  strncpy(ip_str, ipaddr_ntoa(&ipaddr), sizeof(ip_str));
  strncpy(nm_str, ipaddr_ntoa(&netmask), sizeof(nm_str));
  strncpy(gw_str, ipaddr_ntoa(&gw), sizeof(gw_str));
  printf("Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);


#ifdef PERF
  perf_init("/tmp/minimal.perf");
#endif /* PERF */

  sys_sem_new(&sem, 0); /* Create a new semaphore. */
  tcpip_init(tcpip_init_done, sem);
  sys_sem_wait(&sem);    /* Block until the lwIP stack is initialized. */
  sys_sem_free(&sem);    /* Free the semaphore. */

/*  lwip_init(); */

  printf("TCP/IP initialized.\n");

  netif_add(&netif, &ipaddr, &netmask, &gw, NULL, mintapif_init, ethernet_input);
  netif_set_default(&netif);
  netif_set_up(&netif);
#if LWIP_IPV6
  netif_create_ip6_linklocal_address(&netif, 1);
#endif 

#if SNMP_PRIVATE_MIB != 0
  /* initialize our private example MIB */
  lwip_privmib_init();
#endif
  snmp_trap_dst_ip_set(0,&trap_addr);
  snmp_trap_dst_enable(0,trap_flag);
  snmp_set_syscontact(syscontact_str,&syscontact_len);
  snmp_set_syslocation(syslocation_str,&syslocation_len);
  snmp_set_snmpenableauthentraps(&snmpauthentraps_set);
  snmp_init();

  echo_init();

  timer_init();
  timer_set_interval(TIMER_EVT_ETHARPTMR, ARP_TMR_INTERVAL / 10);
  timer_set_interval(TIMER_EVT_TCPTMR, TCP_TMR_INTERVAL / 10);
#if IP_REASSEMBLY
  timer_set_interval(TIMER_EVT_IPREASSTMR, IP_TMR_INTERVAL / 10);
#endif

	ppp_init();

	ppp_desc = pppOverEthernetOpen(&netif, NULL, NULL, pppLinkStatusCallback, NULL);
	printf("ppp_desc = %d\n\r", ppp_desc);

	pppSetAuth(PPPAUTHTYPE_ANY, username, password);

  printf("Applications started.\n");
    
  while (1) {
	mintapif_wait(&netif, 9999999);
  }

#if (NO_SYS == 1)
  while (1) {
    
      /* poll for input packet and ensure
         select() or read() arn't interrupted */
      sigemptyset(&mask);
      sigaddset(&mask, SIGALRM);
      sigprocmask(SIG_BLOCK, &mask, &oldmask);

      /* start of critical section,
         poll netif, pass packet to lwIP */
      if (mintapif_select(&netif) > 0)
      {
        /* work, immediatly end critical section 
           hoping lwIP ended quickly ... */
        sigprocmask(SIG_SETMASK, &oldmask, NULL);
      }
      else
      {
        /* no work, wait a little (10 msec) for SIGALRM */
          sigemptyset(&empty);
          sigsuspend(&empty);
        /* ... end critical section */
          sigprocmask(SIG_SETMASK, &oldmask, NULL);
      }

#if (NO_SYS == 1)
      if(timer_testclr_evt(TIMER_EVT_TCPTMR))
      {
        tcp_tmr();
      }
#if IP_REASSEMBLY
      if(timer_testclr_evt(TIMER_EVT_IPREASSTMR))
      {
        ip_reass_tmr();
      }
#endif
      if(timer_testclr_evt(TIMER_EVT_ETHARPTMR))
      {
        etharp_tmr();
      }
#endif
  }
#endif

  return 0;
}
