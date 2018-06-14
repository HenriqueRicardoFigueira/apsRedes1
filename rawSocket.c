
/*
 * c�digo adaptado/alterdo de: 
 * https://gist.github.com/austinmarton/1922600
 */

/*
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define MY_DEST_MAC0	0xFF
#define MY_DEST_MAC1	0xFF
#define MY_DEST_MAC2	0xFF
#define MY_DEST_MAC3	0xFF
#define MY_DEST_MAC4	0xFF
#define MY_DEST_MAC5	0xFF

#define DEFAULT_IF	"wlan0"
#define BUF_SIZ		1024

struct arp {
  char hw_type[2];
  char pt_type[2];
  char hw_len;
  char pt_len;
  char op[2];
  char sent_hw[6];
  char sent_ip[4];
  char target_hw[6];
  char target_ip[4];
} ;

void preencherStruct()
{
	struct arp arp;
	char url[]="teste.txt";
	FILE *arq;
	
	arq = fopen(url, "r");
	if(arq == NULL)
		printf("Erro, nao foi possivel abrir o arquivo\n");
	else
		fread(&arp,sizeof(arq),1,arq);
			
	
	fclose(arq);
	printf("%s \n",arp.hw_type);
	printf("%s \n",arp.pt_type);
	printf("%s \n",arp.hw_len);

}


int payload(char *sendbuf, int tx_len)
{
        // esse � um exemplo de ARP... 
  	// hw type
	sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x01;
	// proto type
        sendbuf[tx_len++] = 0x08;
        sendbuf[tx_len++] = 0x00;
	// hw len
        sendbuf[tx_len++] = 0x06;
	// proto len
        sendbuf[tx_len++] = 0x04;
	// opcode - request 1 reply 2
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x01;
	// sender MAC
        sendbuf[tx_len++] = 0xB8;
        sendbuf[tx_len++] = 0x76;
        sendbuf[tx_len++] = 0x3F;
        sendbuf[tx_len++] = 0xF5;
        sendbuf[tx_len++] = 0xCD;
        sendbuf[tx_len++] = 0xD3;
	// sender IP
        sendbuf[tx_len++] = 0xC0;
        sendbuf[tx_len++] = 0xA8;
        sendbuf[tx_len++] = 0xED;
        sendbuf[tx_len++] = 0x06;
	// target MAC
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x00;
        sendbuf[tx_len++] = 0x00;
	// target IP
        sendbuf[tx_len++] = 0xC0;
        sendbuf[tx_len++] = 0xA8;
        sendbuf[tx_len++] = 0xED;
        sendbuf[tx_len++] = 0xFE;
  return tx_len;
}

int main(int argc, char *argv[])
{
	preencherStruct();	
	int sockfd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	int tx_len = 0;
	char sendbuf[BUF_SIZ];
	struct ether_header *eh = (struct ether_header *) sendbuf;
	struct iphdr *iph = (struct iphdr *) (sendbuf + sizeof(struct ether_header));
	struct sockaddr_ll socket_address;
	char ifName[IFNAMSIZ];
	
	/* Get interface name */
	if (argc > 1)
		strcpy(ifName, argv[1]);
	else
		strcpy(ifName, DEFAULT_IF);

	/* Open RAW socket to send on */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW)) == -1) {
	    perror("socket");
	}

	/* Get the index of the interface to send on */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFINDEX, &if_idx) < 0)
	    perror("SIOCGIFINDEX");
	/* Get the MAC address of the interface to send on */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
	if (ioctl(sockfd, SIOCGIFHWADDR, &if_mac) < 0)
	    perror("SIOCGIFHWADDR");

	/* Construct the Ethernet header */
	memset(sendbuf, 0, BUF_SIZ);
	/* Ethernet header */
	eh->ether_shost[0] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[0];
	eh->ether_shost[1] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[1];
	eh->ether_shost[2] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[2];
	eh->ether_shost[3] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[3];
	eh->ether_shost[4] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[4];
	eh->ether_shost[5] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[5];
	eh->ether_dhost[0] = MY_DEST_MAC0;
	eh->ether_dhost[1] = MY_DEST_MAC1;
	eh->ether_dhost[2] = MY_DEST_MAC2;
	eh->ether_dhost[3] = MY_DEST_MAC3;
	eh->ether_dhost[4] = MY_DEST_MAC4;
	eh->ether_dhost[5] = MY_DEST_MAC5;
	/* Ethertype field */
	//eh->ether_type = htons(ETH_P_IP);
	eh->ether_type = htons(0x0806);
	tx_len += sizeof(struct ether_header);
 	
	/* Packet data */
	//sendbuf[tx_len++] = 0xde;
	//sendbuf[tx_len++] = 0xad;
	//sendbuf[tx_len++] = 0xbe;
	//sendbuf[tx_len++] = 0xef;
	tx_len = payload(sendbuf,tx_len);


	/* Index of the network device */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;
	/* Address length*/
	socket_address.sll_halen = ETH_ALEN;
	/* Destination MAC */
	socket_address.sll_addr[0] = MY_DEST_MAC0;
	socket_address.sll_addr[1] = MY_DEST_MAC1;
	socket_address.sll_addr[2] = MY_DEST_MAC2;
	socket_address.sll_addr[3] = MY_DEST_MAC3;
	socket_address.sll_addr[4] = MY_DEST_MAC4;
	socket_address.sll_addr[5] = MY_DEST_MAC5;

	/* Send packet */
	if (sendto(sockfd, sendbuf, tx_len, 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	    printf("Send failed\n");

	return 0;
}

