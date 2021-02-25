/*
 * @Author: sdc
 * @Date: 2020-11-10 14:16:52
 * @LastEditTime: 2020-11-20 10:30:59
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /opt/sniffcatch/main.h
 */
#include <clickhouse/client.h>
#include <iostream>

using namespace std;

char * ipAddr (char *dev);
char * getLocalIp();

void getPacket_cpp(unsigned char * arg, const struct pcap_pkthdr * packet_header, const unsigned char * packet_content);
void connectCk();
void insertCk();
void capture();
void loadPcapFile();
void getPacket(unsigned char * arg, const struct pcap_pkthdr * packet_header, const unsigned char * packet_content);


struct ether_header{
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short eth_type;
};

struct ip_header{
    unsigned char header_len:4;
    unsigned char version:4;
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
    unsigned char options;
};

struct tcp_option
{
 char kind:8;
 char size:8;
 char Context[20];
};

struct udp_header
{
    unsigned short int sport;
    unsigned short int dport;
    unsigned short int tot_len;
    unsigned short int check_sum;
};


struct datas
{
    vector<string> id;
    vector<int> rtime;
    vector<string> plen;
    vector<string> smac;
    vector<string> dmac;
    vector<string> sip;
    vector<string> dip;
    vector<string> proto;
    vector<string> sport;
    vector<string> dport;
    vector<string> flag;
    vector<string> file;
    vector<string> seq;
    vector<string> ack;
    vector<string> session_id;
    vector<string> len;
};
