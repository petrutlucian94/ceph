#include <errno.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <ifaddrs.h>

int getifaddrs(struct ifaddrs **ifap)
{
	ULONG subnet = 0;
	PULONG mask = &subnet;
	DWORD size, res, i = 0;
	int ret;
	PIP_ADAPTER_ADDRESSES adapter_addresses, aa;
	PIP_ADAPTER_UNICAST_ADDRESS ua;
	struct ifaddrs *head = NULL;
	struct sockaddr_in *pInAddr = NULL;
	SOCKADDR *pSockAddr = NULL;
	struct ifaddrs *fa;

	res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
				   NULL, NULL, &size);
	if (res != ERROR_BUFFER_OVERFLOW) {
		errno = ENOMEM;
		return -1;
	}

	adapter_addresses = (PIP_ADAPTER_ADDRESSES)malloc(size);
	res = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX,
				   NULL, adapter_addresses, &size);
	if (res != ERROR_SUCCESS) {
		errno = ENOMEM;
		return -1;
	}

	for (aa = adapter_addresses; aa != NULL; aa = aa->Next) {
		if (aa->OperStatus != 1)
			continue;

		for (ua = aa->FirstUnicastAddress; ua != NULL; ua = ua->Next) {
			pSockAddr = ua->Address.lpSockaddr;
			if (pSockAddr->sa_family != AF_INET &&
				pSockAddr->sa_family != AF_INET6)
				continue;
			fa = calloc(sizeof(*fa), 1);
			if (!fa) {
                                errno = ENOMEM;
				ret = -1;
				goto out;
			}

			fa->ifa_next = head;
			head = fa;

			fa->ifa_flags = IFF_UP;
			if (aa->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
				fa->ifa_flags |= IFF_LOOPBACK;

			fa->ifa_addr = (struct sockaddr *) &fa->in_addrs;
			fa->ifa_netmask = (struct sockaddr *) &fa->in_netmasks;
			fa->ifa_name = fa->ad_name;

			if (pSockAddr->sa_family == AF_INET) {
				subnet = 0;
				mask = &subnet;
				if (ConvertLengthToIpv4Mask(ua->OnLinkPrefixLength, mask) !=
					NO_ERROR) {
					errno = 60; /* Missing ENODATA from the project actual value 60 */
					ret = -1;
					goto out;
				}
				struct sockaddr_in *addr4 = (struct sockaddr_in *)
							    &fa->in_addrs;
				struct sockaddr_in *netmask4 = (struct sockaddr_in *)
								&fa->in_netmasks;
				netmask4->sin_family = pSockAddr->sa_family;
				addr4->sin_family = pSockAddr->sa_family;
				netmask4->sin_addr.S_un.S_addr = mask;
				pInAddr = (struct sockaddr_in *) pSockAddr;
				addr4->sin_addr = pInAddr->sin_addr;
			} else {
				struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)
							      &fa->in_addrs;
				(*addr6) = *(struct sockaddr_in6 *) pSockAddr;
			}
			fa->speed = aa->TransmitLinkSpeed;
			// TODO maybe use friendly name instead of adapter GUID
			sprintf_s(fa->ad_name, sizeof(fa->ad_name), aa->AdapterName);
		}
	}
	ret = 0;
out:
	free(adapter_addresses);
	if (ret && head)
		free(head);
	else if (ifap)
		*ifap = head;

	return ret;
}

void freeifaddrs(struct ifaddrs *ifa)
{
	while (ifa) {
		struct ifaddrs *next = ifa->ifa_next;
		free(ifa);
		ifa = next;
	}
}
