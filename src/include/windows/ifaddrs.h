#ifndef IFADDRS_H
#define IFADDRS_H

#include <winsock2.h>

//#define	IFF_UP				1<<0
//#define IFF_LOOPBACK			1<<3

/* here is minimal subset of ifaddr API required for sockets & UDP
   providers */
struct ifaddrs {
	struct ifaddrs  *ifa_next;    /* Next item in list */
	char            *ifa_name;    /* Name of interface */
	unsigned int     ifa_flags;   /* Flags from SIOCGIFFLAGS */
	struct sockaddr *ifa_addr;    /* Address of interface */
	struct sockaddr *ifa_netmask; /* Netmask of interface */

	struct sockaddr_storage in_addrs;
	struct sockaddr_storage in_netmasks;

	char		   ad_name[16];
	size_t		   speed;
};

int getifaddrs(struct ifaddrs **ifap);
void freeifaddrs(struct ifaddrs *ifa);

#endif
