// 출처: https://blog.naver.com/hyun456789/221747571854

#include "get_mac_ip.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int get_ip_addr(char *ip_str, const char *if_name)
{
	struct sockaddr		ip_addr;
	struct sockaddr_in 	*cur_ip_addr;
	struct ifreq ifr;
	int	ret = 0;
	int	fd;
	
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		return -1;
	}
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, if_name);
	if(ioctl(fd, SIOCGIFADDR, &ifr) == 0)
	{
		memcpy(&ip_addr, &ifr.ifr_addr, sizeof(struct sockaddr));
		cur_ip_addr = (struct sockaddr_in*)&ip_addr;
		strcpy(ip_str, inet_ntoa(cur_ip_addr->sin_addr));
		ret =  1;
	}
	
	close(fd);
	return ret;
}

int get_mac(char *mac_str, const char *if_name)
{
	struct sockaddr macaddr;
	struct ifreq ifr;
	int	ret = 0;
	int	fd;

	memset(&macaddr, 0x00, sizeof(macaddr));
	
	if((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
	{
		return -1;
	}
	
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, if_name);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) == 0)
	{
		memcpy(&macaddr, &ifr.ifr_hwaddr, sizeof(ifr.ifr_hwaddr));
		ret =  1;
	}
	
	sprintf(mac_str,"%02x:%02x:%02x:%02x:%02x:%02x",
				(unsigned char)macaddr.sa_data[0],(unsigned char)macaddr.sa_data[1],(unsigned char)macaddr.sa_data[2],
				(unsigned char)macaddr.sa_data[3],(unsigned char)macaddr.sa_data[4],(unsigned char)macaddr.sa_data[5]);

	close(fd);
	return ret;
}