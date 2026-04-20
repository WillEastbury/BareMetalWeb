#ifndef BMW_PICO_LWIPOPTS_H
#define BMW_PICO_LWIPOPTS_H

/* Minimal lwIP config for BareMetalWeb on Pico 2W */
#define NO_SYS                  1
#define LWIP_SOCKET             0
#define LWIP_NETCONN            0
#define MEM_LIBC_MALLOC         0

#define MEM_SIZE                16384
#define MEMP_NUM_TCP_PCB        8
#define MEMP_NUM_TCP_PCB_LISTEN 2
#define MEMP_NUM_TCP_SEG        24
#define MEMP_NUM_PBUF           16
#define PBUF_POOL_SIZE          16
#define PBUF_POOL_BUFSIZE       1536

#define TCP_MSS                 1460
#define TCP_WND                 (4 * TCP_MSS)
#define TCP_SND_BUF             (4 * TCP_MSS)
#define TCP_SND_QUEUELEN        16

#define LWIP_RAW                1
#define LWIP_TCP                1
#define LWIP_UDP                1
#define LWIP_DHCP               1
#define LWIP_ICMP               1
#define LWIP_ARP                1
#define LWIP_DNS                0
#define LWIP_IGMP               0
#define LWIP_IPV6               0

#define LWIP_NETIF_STATUS_CALLBACK 1
#define LWIP_NETIF_LINK_CALLBACK   1

#define LWIP_HTTPD              0
#define LWIP_STATS              0
#define LWIP_DEBUG              0

#endif
