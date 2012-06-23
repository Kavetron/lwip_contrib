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
#include "ppp.h"

#include "netif/sio.h"

/* (manual) host IP configuration */
static ip_addr_t ipaddr, netmask, gw;

/* SNMP trap destination cmd option */
static unsigned char trap_flag;
static ip_addr_t trap_addr;

/* nonstatic debug cmd option, exported in lwipopts.h */
unsigned char debug_flags;

#if 0
int to_pppd[2], from_pppd[2];
#endif

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

void ppp_link_status_cb(ppp_pcb *pcb, int err_code, void *ctx) {
	LWIP_UNUSED_ARG(ctx);

	switch(err_code) {
		case PPPERR_NONE: {             /* No error. */
			struct ppp_addrs *ppp_addrs = &pcb->addrs;
			fprintf(stderr, "ppp_link_status_cb: PPPERR_NONE\n\r");
			fprintf(stderr, "   our_ipaddr  = %s\n\r", ip_ntoa(&ppp_addrs->our_ipaddr));
			fprintf(stderr, "   his_ipaddr  = %s\n\r", ip_ntoa(&ppp_addrs->his_ipaddr));
			fprintf(stderr, "   netmask     = %s\n\r", ip_ntoa(&ppp_addrs->netmask));
			fprintf(stderr, "   dns1        = %s\n\r", ip_ntoa(&ppp_addrs->dns1));
			fprintf(stderr, "   dns2        = %s\n\r", ip_ntoa(&ppp_addrs->dns2));
#if PPP_IPV6_SUPPORT
			fprintf(stderr, "   our6_ipaddr = %s\n\r", ip6addr_ntoa(&ppp_addrs->our6_ipaddr));
			fprintf(stderr, "   his6_ipaddr = %s\n\r", ip6addr_ntoa(&ppp_addrs->his6_ipaddr));
#endif /* PPP_IPV6_SUPPORT */
			break;
		}
		case PPPERR_PARAM: {           /* Invalid parameter. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_PARAM\n\r");
			break;
		}
		case PPPERR_OPEN: {            /* Unable to open PPP session. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_OPEN\n\r");
			break;
		}
		case PPPERR_DEVICE: {          /* Invalid I/O device for PPP. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_DEVICE\n\r");
			break;
		}
		case PPPERR_ALLOC: {           /* Unable to allocate resources. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_ALLOC\n\r");
			break;
		}
		case PPPERR_USER: {            /* User interrupt. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_USER\n\r");
			break;
		}
		case PPPERR_CONNECT: {         /* Connection lost. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_CONNECT\n\r");
			break;
		}
		case PPPERR_AUTHFAIL: {        /* Failed authentication challenge. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_AUTHFAIL\n\r");
			break;
		}
		case PPPERR_PROTOCOL: {        /* Failed to meet protocol. */
			fprintf(stderr, "ppp_link_status_cb: PPPERR_PROTOCOL\n\r");
/*			ppp_desc = ppp_over_ethernet_open(&MACB_if, NULL, NULL, ppp_link_status_cb, NULL);
			printf("ppp_desc = %d\n\r", ppp_desc); */
			break;
		}
		default: {
			fprintf(stderr, "ppp_link_status_cb: unknown err code %d\n\r", err_code);
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

int myprintf(const char *format, ...) {
  va_list args;
  int n;
  va_start(args, format);
  n = vfprintf(stderr, format, args);
  va_end(args);
  return n;
}

#if 0
u32_t sio_write(sio_fd_t fd, u8_t *data, u32_t len) {
  return write(to_pppd[1], data, len);
}

void sio_read_abort(sio_fd_t fd) {
}

void sio_input(ppp_pcb *pcb) {
  u_char buf[1500];
  int len;
  len = read(from_pppd[0], buf, 1500);
  if(len > 0)
    pppos_input(pcb, buf, len);
}
#endif

int
main(int argc, char **argv)
{
  struct netif netif;
  struct netif netif2;
#if (NO_SYS == 1)
  sigset_t mask, oldmask, empty;
#endif
  int ch;
  char ip_str[16] = {0}, nm_str[16] = {0}, gw_str[16] = {0};
  sys_sem_t sem;
  char *username = "essai", *password = "aon0viipheehooX";
  char *username2 = "essai2", *password2 = "aon0viipheehooX";
  ppp_pcb *ppp, *ppp2, *ppps;
  sio_status_t *ser;
  int coin = 0;

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
  fprintf(stderr, "Host at %s mask %s gateway %s\n", ip_str, nm_str, gw_str);


#ifdef PERF
  perf_init("/tmp/minimal.perf");
#endif /* PERF */

  sys_sem_new(&sem, 0); /* Create a new semaphore. */
  tcpip_init(tcpip_init_done, sem);
  sys_sem_wait(&sem);    /* Block until the lwIP stack is initialized. */
  sys_sem_free(&sem);    /* Free the semaphore. */

/*  lwip_init(); */

  fprintf(stderr, "TCP/IP initialized.\n");

  netif_add(&netif, &ipaddr, &netmask, &gw, NULL, mintapif_init, ethernet_input);
/*  netif_set_default(&netif); */
  netif_set_up(&netif);

  IP4_ADDR(&gw, 192,168,1,1);
  IP4_ADDR(&ipaddr, 192,168,1,2);
  IP4_ADDR(&netmask, 255,255,255,0);

  netif_add(&netif2, &ipaddr, &netmask, &gw, NULL, mintapif_init, ethernet_input);
  netif_set_up(&netif2);

#if LWIP_IPV6
  /* netif_create_ip6_linklocal_address(&netif, 1); */
#endif 

  fprintf(stderr, "netif %d\n", netif.num);
  fprintf(stderr, "netif2 %d\n", netif2.num);

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

	ppp = ppp_new();
	ppp2 = ppp_new();
	ppps = ppp_new();

#if PPP_DEBUG
	fprintf(stderr, "ppp = %d\n", ppp->num);
	fprintf(stderr, "ppp2 = %d\n", ppp2->num);
#endif
	fprintf(stderr, "ppp_pcb sizeof(ppp) = %ld\n", sizeof(ppp_pcb));

	ppp_set_auth(ppp, PPPAUTHTYPE_EAP, username, password);
	ppp_over_ethernet_open(ppp, &netif, NULL, NULL, ppp_link_status_cb, NULL);

	ppp_set_auth(ppp2, PPPAUTHTYPE_MSCHAP, username2, password2);
	ppp_over_ethernet_open(ppp2, &netif2, NULL, NULL, ppp_link_status_cb, NULL);

	ser = sio_open(2);
	fprintf(stderr, "SIO FD = %d\n", ser->fd);
	usleep(100000); /* wait a little bit for forked pppd to be ready */

	ppp_set_auth(ppps, PPPAUTHTYPE_PAP, username2, password2);
	ppp_over_serial_open(ppps, ser, ppp_link_status_cb, NULL);
	        
#if 0
	/* start pppd */
	switch(fork()) {
		case -1:
			perror("fork");
			 exit(-1);
		/* child */
		case 0:
			pipe(to_pppd);
			pipe(from_pppd);
			dup2(to_pppd[0],0);
			dup2(from_pppd[1],1);
			execlp("pon", "pon", "test-dialup", NULL) ;
			break;
		/* parent */
		default:
			break;
	}
#endif
  fprintf(stderr, "Applications started.\n");
    
  while (1) {
    fd_set fdset;
    struct timeval tv;
    struct mintapif *mintapif, *mintapif2;
    int ret;
    int maxfd = 0;

    tv.tv_sec = 1;
    tv.tv_usec = 0; /* usec_to; */

    FD_ZERO(&fdset);

    mintapif = netif.state;
    FD_SET(mintapif->fd, &fdset);

    mintapif2 = netif2.state;
    FD_SET(mintapif2->fd, &fdset);

    maxfd = LWIP_MAX(mintapif->fd, mintapif2->fd);
#if 0
    FD_SET(from_pppd[0], &fdset);
#endif

    if(ser) {
      FD_SET(ser->fd, &fdset);
      maxfd = LWIP_MAX(maxfd, ser->fd);
    }

    ret = select( maxfd + 1, &fdset, NULL, NULL, &tv);
    if(ret > 0) {
      if( FD_ISSET(mintapif->fd, &fdset) )
        mintapif_input(&netif);
      if( FD_ISSET(mintapif2->fd, &fdset) )
        mintapif_input(&netif2);
#if 0
      if( FD_ISSET(from_pppd[0], &fdset) )
        sio_input(ppps);
#endif
      if(ser && FD_ISSET(ser->fd, &fdset) ) {
        u8_t buffer[128];
        int len;
        len = sio_read(ser, buffer, 128);
        pppos_input(ppps, buffer, len);
      }
    }

	coin++;
        if(!(coin%1000)) fprintf(stderr, "COIN %d\n", coin);
	if(coin == 4000) {
		/* ppp_close(ppp); */
		ppp = NULL;
	}
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
