/*
 * @Author: your name
 * @Date: 2020-09-22 11:20:52
 * @LastEditTime: 2020-09-25 17:20:49
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /opt/sniffcatch/1.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include <ifaddrs.h>
#include <string.h> 

int *sum = 0;

struct ether_header{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short eth_type;
};

struct ip_header{
    int version:4;
    int header_len:4;
    unsigned char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    unsigned char ttl:8;
    unsigned char protocol:8;
    int checksum:16;
    unsigned char sip[4];
    unsigned char dip[4];
};

struct tcp_header
{
    unsigned short int sport;
    unsigned short int dport;
    unsigned int seq;
    unsigned int ack;
    unsigned char head_len;
    unsigned char flags;
    unsigned short int wind_size;
    unsigned short int check_sum;
    unsigned short int urg_ptr;
};

struct udp_header
{
    unsigned short int sport;
    unsigned short int dport;
    unsigned short int tot_len;
    unsigned short int check_sum;
};


struct result
{
    unsigned short int a;
    unsigned short int b;
};

typedef void (*callback1)(char *res, unsigned int lport, bpf_u_int32 length);

callback1 test1;


char addressBuffer[INET_ADDRSTRLEN], ip[20], direct[10];
char * handle (char *dev)
{
    struct ifaddrs * ifAddrStruct=NULL;
    void * tmpAddrPtr=NULL;
    getifaddrs(&ifAddrStruct);
    
    while (ifAddrStruct!=NULL) 
	{
        if (ifAddrStruct->ifa_addr->sa_family==AF_INET)
		{   // check it is IP4
            // is a valid IP4 Address
            if (!strcmp(ifAddrStruct->ifa_name, dev)){
                // printf("%s\n", ifAddrStruct->ifa_name);
                tmpAddrPtr = &((struct sockaddr_in *)ifAddrStruct->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
                return addressBuffer;
            }
        }
		else if (ifAddrStruct->ifa_addr->sa_family==AF_INET6)
		{   // check it is IP6
            ;;
        } 
        ifAddrStruct = ifAddrStruct->ifa_next;
    }
    return addressBuffer;
}

void getPacket(u_char *arg, const struct pcap_pkthdr *packet_header, const u_char *packet_content){
    int *id = (int *)arg;
    // printf("id: %d\n", ++(*id));
    // printf("Packet length: %d\n", packet_header->len);
    // printf("Number of bytes: %d\n", packet_header->caplen);
    // printf("Received time: %s\n", ctime((const time_t *)&packet_header->ts.tv_sec));
    
    // int i;
    // for(i = 0; i < packet_header->len; ++i){
    //     printf(" %02x", packet_content[i]);
    //     // printf("%s", packet_content[i]);
    //     if((i+1)%16 == 0){
    //         printf("\n");
    //     }
    // }

    unsigned int eth_len=sizeof(struct ether_header);
    unsigned int ip_len=sizeof(struct ip_header);

    unsigned char *mac_string, *sip_string, *dip_string;
    struct ether_header *ethernet_protocol;
    struct ip_header *ip_protocol;
    struct tcp_header *tcp_protocol;
    struct udp_header *udp_protocol;
    unsigned short int ethernet_type, proto, tcp_sport, tcp_dport, udp_sport, udp_dport, port;

    ethernet_protocol = (struct ether_header *)packet_content;
    ip_protocol=(struct ip_header *)(packet_content + eth_len);
    tcp_protocol=(struct tcp_header *)(packet_content + eth_len + ip_len);
    udp_protocol=(struct udp_header *)(packet_content + eth_len + ip_len);
    
    mac_string = (unsigned char *)ethernet_protocol->src_mac;  
    // printf("smac %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    mac_string = (unsigned char *)ethernet_protocol->dst_mac;
    // printf("dmac %02x:%02x:%02x:%02x:%02x:%02x\n", *(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));
    ethernet_type = ntohs(ethernet_protocol->eth_type);
    // printf("Ethernet type is :%04x\n", ethernet_type);

    sip_string = (unsigned char *)ip_protocol->sip;  
    dip_string = (unsigned char *)ip_protocol->dip;
    proto = ip_protocol->protocol;
    tcp_sport = ntohs(tcp_protocol->sport);
    tcp_dport = ntohs(tcp_protocol->dport);
    udp_sport = ntohs(udp_protocol->sport);
    udp_dport = ntohs(udp_protocol->dport);
    char sip[80], dip[80];
    switch(ethernet_type)  
    {
        case 0x0800: //ip
            // printf("The network layer is IP protocol\n");
            sprintf(sip, "%d.%d.%d.%d", sip_string[0], sip_string[1], sip_string[2], sip_string[3]);
            sprintf(dip, "%d.%d.%d.%d", dip_string[0], dip_string[1], dip_string[2], dip_string[3]);
            // printf("sip %s\n", sip);
            // printf("dip %s\n", dip);
            // printf("protocol : %04x\n", proto);
            // 通过IP判断流量方向：上行/下行
            if (strcmp(ip, sip) == 0){
                strncpy(direct, "tx", 10);
            }
            else if(strcmp(ip, dip) == 0){
                strncpy(direct, "rx", 10);
            }
            // printf("direct %s\n", direct);
            if (proto == 0x0006){  //tcp
                if (strcmp(direct, "rx")==0){
                    port = tcp_dport;
                }
                else if (strcmp(direct, "tx")==0){
                    port = tcp_sport;
                }
                // printf("protocol : tcp\n");
                // printf("sport : %u\n", tcp_sport);
                // printf("dport : %u\n", tcp_dport);
            }
            else if(proto == 0x0011){  //udp
                if (strcmp(direct, "rx")==0){
                    port = udp_dport;
                }
                else if (strcmp(direct, "tx")==0){
                    port = udp_sport;
                }
                // printf("protocol : udp\n");
                // printf("sport : %u\n", udp_sport);
                // printf("dport : %u\n", udp_dport);
            }
            else if(proto == 0x0002){  //igmp
                // printf("igmp Protocol!\n");
                ;;
            }
            else if(proto == 0x0001){  //icmp
                ;;
                // printf("icmp Protocol!\n");
                // print("ICMP Type: %d   ",icmpheader->icmp_type);
                // switch (icmp_type)
                // {
                //    case 0x08:
                //        print("(ICMP Request)\n");
                //        break;
                //    case 0x00:
                //        print("(ICMP Response)\n");
                //        break;
                //    case 0x11:
                //        print("(Timeout!!!)\n");
                //        break;
                // }
            }
            else{
                // printf("other transport protocol is used\n");
            }
            break;
        case 0x0806: //arp
            // printf("The network layer is ARP protocol\n");
            break;
        case 0x0835: //rarp
            // printf("The network layer is RARP protocol\n");
            break;
        case 0x86DD: //ipv6
			// printf("IPv6 protocol!\n");
			break;
        case 0x880B: //PPP
			// printf("PPP protocol!\n");
			break;
        default:break;
    }
    // printf("%u\n", port);
    test1(direct, port, packet_header->len);
    // printf("\n\n");
}

int handle1(callback1 getPacket1){
    test1 = getPacket1;
    char *devStr, errBuf[PCAP_ERRBUF_SIZE];
    devStr = pcap_lookupdev(errBuf);
    if(devStr){
        printf("success: device: %s\n", devStr);
    }
    else{
        // printf("error: %s\n", errBuf);
        exit(1);
    }

    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if(!device){
        // printf("error: pcap_live_open(): %s\n", errBuf);
        exit(1);
    }

    char *dev = devStr;
    strncpy(ip, handle(dev), 20);
    int sum=0;
    // printf("sum: %d\n",  sum);
    pcap_loop(device, -1, getPacket, (unsigned char *)&sum);
    pcap_close(device);
    return 0;
}