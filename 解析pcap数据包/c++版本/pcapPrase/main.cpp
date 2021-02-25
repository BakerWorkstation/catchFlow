/*
 * @Author: sdc
 * @Date: 2020-11-10 16:56:50
 * @LastEditTime: 2020-12-28 16:13:04
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /opt/sniffcatch/main.cpp
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h> 
#include <iostream>
#include <clickhouse/client.h>
#include <string>
#include "main.h"
#include "clickhouse.h"
#include <fstream>
#include<sstream>
#include <iomanip>
using namespace std;
using namespace clickhouse;

char addressBuffer[INET_ADDRSTRLEN];
string file="/opt/sniffcatch/pcap/1.pcap";


datas insertData;
datas *pointer=&insertData;

char * getLocalIp(){
    char *devStr, errBuf[PCAP_ERRBUF_SIZE], *ip;
    //返回第一个合适的网络接口的字符串指针
    devStr = pcap_lookupdev(errBuf);
    char *dev = devStr;
    ip = ipAddr(dev);
    return ip;
}


char * ipAddr (char *dev)
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
                printf("%s\n", ifAddrStruct->ifa_name);
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


/*
 * <离线解析PCAP文件函数>
 * 
 * 1. 可设置PCAP文件绝对路径
 * 2. 可设置filter过滤条件
 * 3. 对每个数据包调用"数据处理回调函数"
 * 
 */
void loadPcapFile(){
    char *localip;
    localip = getLocalIp();
    cout << "ip " << localip << endl;

    char filter_app[] = "";
    pcap_t * handle;
    char error[100];
    int id = 1;
    struct bpf_program filter;
    //函数功能：打开以前保存捕获数据包的文件，用于读取。
    if((handle=pcap_open_offline(file.c_str(), error))==NULL)  //打开文件
    {
        printf("%s\n",error);
        exit(0);
    }
    pcap_compile(handle, &filter, filter_app, 1, 0);//函数返回-1为失败
 
    if(pcap_setfilter(handle, &filter)==0)//成功返回0.不成功返回-1
        pcap_loop( handle, -1, getPacket_cpp, (unsigned char *)&id);
}


/*
 * <捕获网卡实时流量函数>
 * 
 * 1. 抓取本机网卡流量
 * 2. 对每个数据包调用"数据处理回调函数"
 * 
 */
void capture(){
    char *devStr, errBuf[PCAP_ERRBUF_SIZE];
    devStr = pcap_lookupdev(errBuf);
    if(devStr){
        printf("success: device: %s\n", devStr);
    }
    else{
        printf("error: %s\n", errBuf);
        exit(0);
    }
    int id=0 ;

    pcap_t * device = pcap_open_live(devStr, 65535, 1, 0, errBuf);
    if(!device){
        printf("error: pcap_live_open(): %s\n", errBuf);
        exit(0);
    }
    // printf("%s\n", device);
    // pcap_dumper_t* out_pcap;
    // out_pcap  = pcap_dump_open(device,"pack.pcap");
    pcap_loop(device, -1, getPacket_cpp, (unsigned char *)&id);
    // pcap_dump_flush(out_pcap);
    // pcap_dump_close(out_pcap);
    pcap_close(device);
}


/*
 * <数据处理回调函数>
 * 
 * 1. 解析以太层数据，获取源MAC和目的MAC
 * 2. 解析网络层数据，获取源IP和目的IP
 * 3. 解析传输层数据，获取源端口和目的端口
 * 
 */
void getPacket(unsigned char * arg, const struct pcap_pkthdr * packet_header, const unsigned char * packet_content){
    int *id = (int *)arg;

    char * smac = (char*)malloc(20);         // 源mac
    char * dmac = (char*)malloc(20);         // 目的mac
    char * sip = (char*)malloc(20);          // 源ip
    char * dip = (char*)malloc(20);          // 目的ip
    char * protocol = (char*)malloc(10);     // 协议
    char * sport = (char*)malloc(10);        // 源端口
    char * dport = (char*)malloc(10);        // 目的端口
    char * flag = (char*)malloc(10);         // tcp会话标识
    char * seq = (char*)malloc(30);          // tcp会话seq编号
    char * ack = (char*)malloc(30);          // tcp会话ack编号
    char * session_id = (char*)malloc(20);   // tcp会话六元组异或哈希值

    string smac_str,dmac_str,sip_str,dip_str,protocol_str,sport_str,dport_str,flag_str,seq_str,ack_str,session_id_str;
    memset(smac, 0, 20);
    memset(dmac, 0, 20);
    memset(sip, 0, 20);
    memset(dip, 0, 20);
    memset(protocol, 0, 20);
    memset(sport, 0, 20);
    memset(dport, 0, 20);
    memset(flag, 0, 20);
    memset(seq, 0, 20);
    memset(ack, 0, 20);
    memset(session_id, 0, 20);

    int tcp_flag;
    unsigned char *smac_string, *dmac_string, *sip_string, *dip_string;
    unsigned short int ethernet_type, proto, tcp_sport, tcp_dport, udp_sport, udp_dport; 
    unsigned int eth_len=sizeof(struct ether_header), ip_len=0, tcp_len=0, plen=0, rtime=0, tcp_ack=0, tcp_seq=0, len=0;

    struct ip_header *ip_protocol;
    struct tcp_header *tcp_protocol;
    struct udp_header *udp_protocol;
    struct ether_header *ethernet_protocol;

    ethernet_protocol = (struct ether_header *)packet_content;
    ip_protocol=(struct ip_header *)(packet_content + eth_len);
    // 解析IP报头中 报头大小，得到字长，乘以4得到字节数
    ip_len = (int)(ip_protocol->header_len) * 4;
    tcp_protocol=(struct tcp_header *)(packet_content + eth_len + ip_len);
    udp_protocol=(struct udp_header *)(packet_content + eth_len + ip_len);

    // 解析TCP报头中 报头大小，取高四位得到字长，乘以4得到字节数
    tcp_len = (int)(tcp_protocol->head_len >> 4) * 4;

    // 解析包头，获取包长度和时间戳
    plen = packet_header->len;
    rtime = (unsigned int)packet_header->ts.tv_sec;

    // 解析以太层，获取源MAC地址和目的MAC地址
    vector<unsigned char> smac_string_t;
    smac_string = (unsigned char *)ethernet_protocol->src_mac;
    dmac_string = (unsigned char *)ethernet_protocol->dst_mac;

    sprintf(smac, "%02x:%02x:%02x:%02x:%02x:%02x", smac_string[0], smac_string[1], smac_string[2], smac_string[3], smac_string[4], smac_string[5]);
    sprintf(dmac, "%02x:%02x:%02x:%02x:%02x:%02x", dmac_string[0], dmac_string[1], dmac_string[2], dmac_string[3], dmac_string[4], dmac_string[5]);

    // 获取网络层协议 ->  IP/ARP/RARP/IPv6/PPP
    ethernet_type = ntohs(ethernet_protocol->eth_type);

    switch(ethernet_type)  
    {
        case 0x0800:  // IP层
            strcpy(protocol, "IP");
            // 获取源IP和目的IP
            sip_string = (unsigned char *)ip_protocol->sip;  
            dip_string = (unsigned char *)ip_protocol->dip;
            sprintf(sip, "%u.%u.%u.%u", sip_string[0], sip_string[1], sip_string[2], sip_string[3]);
            sprintf(dip, "%u.%u.%u.%u", dip_string[0], dip_string[1], dip_string[2], dip_string[3]);
            
            // 通过IP判断流量方向：上行/下行
            // char direct[10] = "";
            // if (!strcmp(ip, sip)){
            //     direct = "out";
            // }
            // else if(!strcmp(ip, dip)){
            //     direct = "in";
            // }
            // printf("direct: %s\n", direct);

            // 解析传输层协议
            proto = ip_protocol->protocol;

            switch(proto){
                case 0x0006: // TCP层
                    strcpy(protocol, "TCP");
                    // 获取应用层包大小
                    len = ntohs(ip_protocol->total_len) - ip_len - tcp_len;

                    // 获取源端口和目的端口
                    tcp_sport = ntohs(tcp_protocol->sport);
                    tcp_dport = ntohs(tcp_protocol->dport);
                    sprintf(sport, "%u", tcp_sport);
                    sprintf(dport, "%u", tcp_dport);

                    // 获取seq编号值和ack编号值
                    tcp_ack = ntohl(tcp_protocol->ack);
                    tcp_seq = ntohl(tcp_protocol->seq);
                    sprintf(ack, "%u", tcp_ack);
                    sprintf(seq, "%u", tcp_seq);

                    // 获取tcp会话标识
                    tcp_flag = ntohs(tcp_protocol->flags);

                    // 更新会话标志
                    switch (tcp_flag)
                    {
                        case 0x1000:
                            strcpy(flag, "ACK");
                            break;
                        case 0x0100:
                            strcpy(flag, "FIN");
                            break;
                        case 0x0200:
                            strcpy(flag, "SYN");
                            break;
                        case 0x0400:
                            strcpy(flag, "RST");
                            break;
                        case 0x0800:
                            strcpy(flag, "PSH");
                            break;
                        case 0x1800:
                            strcpy(flag, "PSH ACK");
                            break;
                        case 0x1100:
                            strcpy(flag, "FIN ACK");
                            break;
                        case 0x1200:
                            strcpy(flag, "SYN ACK");
                            break;
                        case 0x2000:
                            strcpy(flag, "URG");
                            break;
                        case 0x4000:
                            strcpy(flag, "ECE");
                            break;
                        case 0x8000:
                            strcpy(flag, "CWR");
                            break;
                        default:
                            break;
                    }
                    break;
                case 0x0011:  // UDP层
                    strcpy(protocol, "UDP");

                    // 获取数据报包大小
                    len = ntohs(ip_protocol->total_len) - ip_len;

                    // 获取源端口和目的端口
                    udp_sport = ntohs(udp_protocol->sport);
                    udp_dport = ntohs(udp_protocol->dport);
                    sprintf(sport, "%u", udp_sport);
                    sprintf(dport, "%u", udp_dport);
                    break;
                case 0x0002:  // IGMP层
                    strcpy(protocol, "IGMP");
                    break;
                case 0x0001:  // ICMP层
                    strcpy(protocol, "ICMP");
                    // printf("ICMP Type: %d   ",icmpheader->icmp_type);
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
                    break;
                default:break;
            }
            break;
        case 0x0806: // ARP层
            strcpy(protocol, "ARP");
            break;
        case 0x0835: // RARP层
            strcpy(protocol, "RARP");
            break;
        case 0x86DD: // IPv6层
            strcpy(protocol, "IPv6");
			break;
        case 0x880B: // PPP层
            strcpy(protocol, "PPP");
			break;
        default:break;
    }

    if (sport && dport){
        sprintf(session_id, "%d", atoi(sip)^atoi(dip)^atoi(sport)^atoi(dport));
    }
    else if(sip && dip){
        sprintf(session_id, "%d", atoi(sip)^atoi(dip));
    }
    else{
        sprintf(session_id, "%d", atoi(smac)^atoi(dmac));
    }
    // cout << "id : " << *id << endl;
    // cout << "Received time : " << rtime << endl;
    // cout << "Packet length : " << plen << endl;
    // cout << "smac : " << smac << endl;
    // cout << "dmac : " << dmac << endl;
    // cout << "sip : " << sip << endl;
    // cout << "dip : " << dip << endl;
    // cout << "protocol : " << protocol << endl;
    // cout << "sport : " << sport << endl;
    // cout << "dport : " << dport << endl;
    // cout << "flag : " << flag << endl;
    // cout << "file : " << file << endl;
    // cout << "seq : " << seq << endl;
    // cout << "ack : " << ack << endl;
    // cout << "len : " << len << endl;
    // cout << "session : " << session_id << endl;
    // cout << "\n\n"<< endl;
    // pointer->id = ++(*id);
    // pointer->rtime = rtime;
    pointer->id.push_back(to_string(*id));
    pointer->rtime.push_back(rtime);
    pointer->plen.push_back(to_string(plen));
    pointer->smac.push_back(smac);
    pointer->dmac.push_back(dmac);
    pointer->sip.push_back(sip);
    pointer->dip.push_back(dip);
    pointer->proto.push_back(protocol);
    pointer->sport.push_back(sport);
    pointer->dport.push_back(dport);
    pointer->flag.push_back(flag);
    pointer->file.push_back(file);
    pointer->seq.push_back(seq);
    pointer->ack.push_back(ack);
    pointer->session_id.push_back(session_id);
    pointer->len.push_back(to_string(len));
    (*id)++;
    // insertCk();
}

void getPacket_cpp(unsigned char * arg, const struct pcap_pkthdr * packet_header, const unsigned char * packet_content){
    int *id = (int *)arg;
    // pcap_dump(arg, pkthdr, packet);
    // cout<< *id << endl;
    // pcap_dump((u_char*)arg, packet_header, packet_content); 
    string sip_str,dip_str,protocol_str,sport_str,dport_str,flag_str,seq_str,ack_str,session_id_str;
    // if (*id < 146 or *id > 149)
    // {
    //     (*id)++;
    //     return ;
    // }
    int tcp_flag=0;
    // vector<unsigned char> sip_string, dip_string;
    unsigned char *sip_string, *dip_string;
    unsigned short int ethernet_type=0, proto=0, sport=0, dport=0, sip_value=0, dip_value=0; 
    unsigned int eth_len=sizeof(struct ether_header), ip_len=0, tcp_len=0, plen=0, rtime=0, tcp_ack=0, tcp_seq=0, len=0;

    struct ether_header *ethernet_protocol;
    struct ip_header *ip_protocol;
    struct tcp_header *tcp_protocol;
    struct udp_header *udp_protocol;

    ethernet_protocol = (struct ether_header *)packet_content;
    ip_protocol=(struct ip_header *)(packet_content + eth_len);
    // 解析IP报头中 报头大小，得到字长，乘以4得到字节数
    ip_len = (int)(ip_protocol->header_len) * 4;
    tcp_protocol=(struct tcp_header *)(packet_content + eth_len + ip_len);
    udp_protocol=(struct udp_header *)(packet_content + eth_len + ip_len);

    // 解析TCP报头中 报头大小，取高四位得到字长，乘以4得到字节数
    tcp_len = (int)(tcp_protocol->head_len >> 4) * 4;

    // 解析包头，获取包长度和时间戳
    plen = packet_header->len;
    rtime = (unsigned int)packet_header->ts.tv_sec;

    // 解析以太层，获取源MAC地址和目的MAC地址
    vector<unsigned char> smac_string(ethernet_protocol->src_mac,ethernet_protocol->src_mac+sizeof(ethernet_protocol->src_mac));
    vector<unsigned char> dmac_string(ethernet_protocol->dst_mac,ethernet_protocol->dst_mac+sizeof(ethernet_protocol->dst_mac));

    std::stringstream smac_str, dmac_str, sip, dip;
    smac_str<<setfill('0')<<hex<<setw(2)<<(int)smac_string[0]<<":"<<setfill('0')<<hex<<setw(2)<<(int)smac_string[1]<<":"<<setfill('0')<<hex<<setw(2)<<(int)smac_string[2]<<":"<<setfill('0')<<hex<<setw(2)<<(int)smac_string[3]<<":"<< setfill('0')<<hex<<setw(2)<<(int)smac_string[4]<<":"<<setfill('0')<<hex<<setw(2)<<(int)smac_string[5];
    dmac_str<<setfill('0')<<hex<<setw(2)<<(int)dmac_string[0]<<":"<<setfill('0')<<hex<<setw(2)<<(int)dmac_string[1]<<":"<<setfill('0')<<hex<<setw(2)<<(int)dmac_string[2]<<":"<<setfill('0')<<hex<<setw(2)<<(int)dmac_string[3]<<":"<< setfill('0')<<hex<<setw(2)<<(int)dmac_string[4]<<":"<<setfill('0')<<hex<<setw(2)<<(int)dmac_string[5];


    // 获取网络层协议 ->  IP/ARP/RARP/IPv6/PPP
    ethernet_type = ntohs(ethernet_protocol->eth_type);

    switch(ethernet_type)  
    {
        case 0x0800:  // IP层
           {
                protocol_str="IP";
                // 获取源IP和目的IP
                sip_string = (unsigned char *)ip_protocol->sip;  
                dip_string = (unsigned char *)ip_protocol->dip;
                vector<unsigned char> sip_temp(ip_protocol->sip,ip_protocol->sip+sizeof(ip_protocol->sip));
                vector<unsigned char> dip_temp(ip_protocol->dip,ip_protocol->dip+sizeof(ip_protocol->dip));
                sip<<(int)sip_temp[0]<<"."<<(int)sip_temp[1]<<"."<<(int)sip_temp[2]<<"."<<(int)sip_temp[3];
                dip<<(int)dip_temp[0]<<"."<<(int)dip_temp[1]<<"."<<(int)dip_temp[2]<<"."<<(int)dip_temp[3];
                sip_value = (int)sip_string[0] * 256 * 256 * 256 + (int)sip_string[1] * 256 * 256 + (int)sip_string[2] * 256 + int(sip_string[3]);
                dip_value = (int)dip_string[0] * 256 * 256 * 256 + (int)dip_string[1] * 256 * 256 + (int)dip_string[2] * 256 + int(dip_string[3]);
            }

            // 通过IP判断流量方向：上行/下行
            // char direct[10] = "";
            // if (!strcmp(ip, sip)){
            //     direct = "out";
            // }
            // else if(!strcmp(ip, dip)){
            //     direct = "in";
            // }
            // printf("direct: %s\n", direct);

            // 解析传输层协议
            proto = ip_protocol->protocol;

            switch(proto){
                case 0x0006: // TCP层
                {
                    protocol_str="TCP";
                    // 获取应用层包大小
                    len = ntohs(ip_protocol->total_len) - ip_len - tcp_len;
                    // cout << "id : " << *id << endl;
                    // cout << tcp_protocol->options << endl;
                    // 处理options
                    // uint16_t mss;
                    // uint8_t* opt = (uint8_t*)(packet_content +  tcp_len -20);
                    uint8_t* opt=(uint8_t *)(packet_content + eth_len + ip_len + tcp_len);
                    // cout << opt << endl;
                    // printf("%s\n", opt);
                    // printf("%s\n", packet_content);
                    // tcp_option * _opt = (tcp_option*)opt;
                    // cout << (unsigned int)_opt->kind << endl;
                    // while( *opt ) {
                    //   tcp_option * _opt = (tcp_option*)opt;
                    //   if( _opt->kind == 1 /* NOP */ ) {
                    //      ++opt;  // NOP is one byte;
                    //      continue;
                    //   }
                    //   if( _opt->kind == 2 /* MSS */ ) {
                    //     mss = ntohs((uint16_t)*(opt + sizeof(opt)));
                    //   }
                    // if( _opt->kind == 5 /* SACK Block */ ) {
                    //     mss = ntohs((uint16_t)*(opt + sizeof(opt)));
                    //     cout << _opt->kind << endl;
                    // }
                    // cout << _opt->size << endl;
                    //   opt -= _opt->size;
                    // }

                    // 获取源端口和目的端口
                    sport = ntohs(tcp_protocol->sport);
                    dport = ntohs(tcp_protocol->dport);

                    // 获取seq编号值和ack编号值
                    tcp_ack = ntohl(tcp_protocol->ack);
                    tcp_seq = ntohl(tcp_protocol->seq);
                    std::stringstream temp_ack,temp_seq;
                    temp_ack  <<dec << tcp_ack;
                    temp_seq  <<dec << tcp_seq;
                    ack_str =temp_ack.str();
                    seq_str =temp_seq.str();

                    // 获取tcp会话标识
                    tcp_flag = ntohs(tcp_protocol->flags);

                    // 更新会话标志
                    switch (tcp_flag)
                    {
                        case 0x1000:
                            flag_str="ACK";
                            break;
                        case 0x0100:
                            flag_str="FIN";
                            break;
                        case 0x0200:

                            flag_str="SYN";
                            break;
                        case 0x0400:
                            flag_str="RST";
                            break;
                        case 0x0800:
                            flag_str="PSH";
                            break;
                        case 0x1800:
                            flag_str="PSH ACK";
                            break;
                        case 0x1100:
                            flag_str="FIN ACK";
                            break;
                        case 0x1200:
                            flag_str="SYN ACK";
                            break;
                        case 0x2000:
                             flag_str="URG";
                            break;
                        case 0x4000:
                            flag_str="ECE";
                            break;
                        case 0x8000:
                            flag_str="CWR";
                            break;
                        default:
                            break;
                    }
                }
                    break;
                case 0x0011:  // UDP层
                {
                    protocol_str="UDP";
                    // 获取数据报包大小
                    len = ntohs(ip_protocol->total_len) - ip_len;

                    // 获取源端口和目的端口
                    sport = ntohs(udp_protocol->sport);
                    dport = ntohs(udp_protocol->dport);
                }
                    break;
                case 0x0002:  // IGMP层
                    protocol_str="IGMP";
                    break;
                case 0x0001:  // ICMP层
                    protocol_str="ICMP";
                    // printf("ICMP Type: %d   ",icmpheader->icmp_type);
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
                    break;
                default:break;
            }
            break;
        case 0x0806: // ARP层
            protocol_str="ARP";
            break;
        case 0x0835: // RARP层
            protocol_str="RARP";
            break;
        case 0x86DD: // IPv6层
            protocol_str="IPv6";
			break;
        case 0x880B: // PPP层
            protocol_str="PPP";
			break;
        default:
            break;
    }

    std::stringstream temp_sport, temp_dport;
    temp_sport  <<dec << sport;
    temp_dport  <<dec << dport;
    sport_str =temp_sport.str();
    dport_str =temp_dport.str();

    if (sport && dport){
        std::stringstream temp_session;
        int flag = sport ^ dport ^ sip_value ^ dip_value;
        temp_session<<dec<<flag;
        session_id_str = temp_session.str();
    }
    else if (sip_value && dip_value ){
        std::stringstream temp_session;
        int flag = sip_value ^ dip_value;
        temp_session<<dec<<flag;
        session_id_str = temp_session.str();
    }
    else{
        std::stringstream temp_session;
        int flag = 0;
        temp_session<<dec<<flag;
        session_id_str = temp_session.str();
    }

    // cout << "id : " << ++(*id) << endl;
    // cout << "Received time : " << rtime << endl;
    // cout << "Packet length : " << plen << endl;
    // cout << "smac : " << smac_str << endl;
    // cout << "dmac : " << dmac_str << endl;
    // cout << "sip : " << sip_str << endl;
    // cout << "dip : " << dip_str << endl;
    // cout << "protocol : " << protocol_str << endl;
    // cout << "sport : " << sport_str << endl;
    // cout << "dport : " << dport_str << endl;
    // cout << "flag : " << flag_str << endl;
    // cout << "file : " << file << endl;
    // cout << "seq : " << seq_str << endl;
    // cout << "ack : " << ack_str << endl;
    // cout << "len : " << len << endl;
    // cout << "session : " << session_id_str << endl;
    // cout << "\n\n"<< endl;
    if (sport_str == "0"){
        sport_str = "";
    }
    if (dport_str == "0"){
        dport_str = "";
    }

    # if 0
    id1->Append(to_string(*id));
    rtime1->Append(rtime);
    plen1->Append(to_string(plen));
    smac1->Append(smac_str.str());
    dmac1->Append(dmac_str.str());
    sip1->Append(sip.str());
    dip1->Append(dip.str());
    proto1->Append(protocol_str);
    sport1->Append(sport_str);
    dport1->Append(dport_str);
    flag1->Append(flag_str);
    file1->Append(file);
    seq1->Append(seq_str);
    ack1->Append(ack_str);
    session_id1->Append(session_id_str);
    len1->Append(to_string(len));
    (*id)++;
    # else
    pointer->id.push_back(to_string(*id));
    pointer->rtime.push_back(rtime);
    pointer->plen.push_back(to_string(plen));
    pointer->smac.push_back(smac_str.str());
    pointer->dmac.push_back(dmac_str.str());
    pointer->sip.push_back(sip.str());
    pointer->dip.push_back(dip.str());
    pointer->proto.push_back(protocol_str);
    pointer->sport.push_back(sport_str);
    pointer->dport.push_back(dport_str);
    pointer->flag.push_back(flag_str);
    pointer->file.push_back(file);
    pointer->seq.push_back(seq_str);
    pointer->ack.push_back(ack_str);
    pointer->session_id.push_back(session_id_str);
    pointer->len.push_back(to_string(len));
    (*id)++;
    # endif
    // insertCk();
}

/*
 * <数据插入clickhouse函数>
 * 
 * 1. 
 * 2. 
 * 3. 
 * 
 */
void insertCk()
{
    cout << "  --- " << pointer->rtime.size() << endl;

    // client.Execute("CREATE TABLE IF NOT EXISTS default.numbers (id UInt64, name String) ENGINE = Memory");
    // Block block;

    // auto id = std::make_shared<ColumnUInt64>();
    // id->Append(1);
    // id->Append(7);

    // auto name = std::make_shared<ColumnString>();
    // name->Append("one");
    // name->Append("seven");

    // block.AppendColumn("id"  , id);
    // block.AppendColumn("name", name);

    // client.Insert("default.numbers", block);
}


void connectCk(){
    string host="10.255.175.94";
    string passwd="antiy?pmc";
    string User ="default";
    int port = 9000;
    //初始化句柄
    ClickHouse HandleClick(host,passwd,User,port);

    string tablename="default.test111";
    //创建数据库表
    // map<string,string> p;
    // p.insert(pair<string,string>("id","UInt64"));
    // p.insert(pair<string,string>("name","String"));
    // HandleClick.MakeTable(tablename,p);

    // //批量插入数据第一列
    // vector<int> vec_p;
    // vector<string> vec_p_str;
    // for(int i=0;i<1000000;i++)
    // {
    //     vec_p.push_back(i);
    //     vec_p_str.push_back(to_string(i));
    // }
    
    auto id = std::make_shared<ColumnString>();
    auto rtime = std::make_shared<ColumnDateTime>();
    auto plen = std::make_shared<ColumnString>();
    auto smac = std::make_shared<ColumnString>();
    auto dmac = std::make_shared<ColumnString>();
    auto sip = std::make_shared<ColumnString>();
    auto dip = std::make_shared<ColumnString>();
    auto proto = std::make_shared<ColumnString>();
    auto sport = std::make_shared<ColumnString>();
    auto dport = std::make_shared<ColumnString>();
    auto flag = std::make_shared<ColumnString>();
    auto file = std::make_shared<ColumnString>();
    auto seq = std::make_shared<ColumnString>();
    auto ack = std::make_shared<ColumnString>();
    auto session_id = std::make_shared<ColumnString>();
    auto len = std::make_shared<ColumnString>();

    Block block;
    # if 0
    HandleClick.AppBlock("id", id1, block);
    HandleClick.AppBlock("r_time", rtime1, block);
    HandleClick.AppBlock("plen", plen1, block);
    HandleClick.AppBlock("smac", smac1, block);
    HandleClick.AppBlock("dmac", dmac1, block);
    HandleClick.AppBlock("sip", sip1, block);
    HandleClick.AppBlock("dip", dip1, block);
    HandleClick.AppBlock("proto", proto1, block);
    HandleClick.AppBlock("sport", sport1, block);
    HandleClick.AppBlock("dport", dport1, block);
    HandleClick.AppBlock("flag", flag1, block);
    HandleClick.AppBlock("file", file1, block);
    HandleClick.AppBlock("seq", seq1, block);
    HandleClick.AppBlock("ack", ack1, block);
    HandleClick.AppBlock("session_id", session_id, block);
    HandleClick.AppBlock("len", len, block);
    # else
        // 
        HandleClick.AppendDatas(id, pointer->id);
        HandleClick.AppendDatas(rtime, pointer->rtime);
        HandleClick.AppendDatas(plen, pointer->plen);
        HandleClick.AppendDatas(smac, pointer->smac);
        HandleClick.AppendDatas(dmac, pointer->dmac);
        HandleClick.AppendDatas(sip, pointer->sip);
        HandleClick.AppendDatas(dip, pointer->dip);
        HandleClick.AppendDatas(proto, pointer->proto);
        HandleClick.AppendDatas(sport, pointer->sport);
        HandleClick.AppendDatas(dport, pointer->dport);
        HandleClick.AppendDatas(flag, pointer->flag);
        HandleClick.AppendDatas(file, pointer->file);
        HandleClick.AppendDatas(seq, pointer->seq);
        HandleClick.AppendDatas(ack, pointer->ack);
        HandleClick.AppendDatas(session_id, pointer->session_id);
        HandleClick.AppendDatas(len, pointer->len);

        HandleClick.AppBlock("id", id, block);
        HandleClick.AppBlock("r_time", rtime, block);
        HandleClick.AppBlock("plen", plen, block);
        HandleClick.AppBlock("smac", smac, block);
        HandleClick.AppBlock("dmac", dmac, block);
        HandleClick.AppBlock("sip", sip, block);
        HandleClick.AppBlock("dip", dip, block);
        HandleClick.AppBlock("proto", proto, block);
        HandleClick.AppBlock("sport", sport, block);
        HandleClick.AppBlock("dport", dport, block);
        HandleClick.AppBlock("flag", flag, block);
        HandleClick.AppBlock("file", file, block);
        HandleClick.AppBlock("seq", seq, block);
        HandleClick.AppBlock("ack", ack, block);
        HandleClick.AppBlock("session_id", session_id, block);
        HandleClick.AppBlock("len", len, block);

    # endif
    
    
    HandleClick.Insert(tablename,block);
}


int main(){
    // loadPcapFile();
    capture();
    connectCk();
    return 0;
}
