#ifndef CORE_H
#define CORE_H

#endif // CORE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <net/ethernet.h>
#include <net/if.h>

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>

#include <arpa/inet.h>
#include <signal.h>
#include <time.h>

#include"data_all.h"
//opt和包的显示
#define IFRLEN 20//network interface length
#define MAXSIZE 4096//buffer size

#include<string>
#include<vector>
#include<QThread>
using namespace std;

class Core{
public:
    static unsigned int submask;
    static string res;
    static bool stop;

    static string start_time;
    static string end_time;
    static string mac_board;
    static string mac_short;
    static string mac_long;
    static string mac_byte;
    static string mac_packet;
    static string bit_s;
    static string mac_byte_speed;
    static string mac_packet_speed;
    static string ip_broadcast;
    static string ip_byte;
    static string ip_packet;
    static string udp_packet;
    static string tcp_packet;
    static string icmp_packet;
    static string icmp_redir;
    static string icmp_des;

    static void init();
    static void print_ethernet(struct ether_header *eth);
    static char* mac_ntoa(u_char *d);
    static void print_arp(struct ether_arp *arp);
    static void print_ip(struct ip *ip);
    static char* ip_ttoa(int flag);
    static char* ip_ftoa(int flag);
    static void print_icmp(struct icmp *icmp);
    static void print_tcp(struct tcphdr *tcp);
    static char* tcp_ftoa(int flag);
    static void print_udp(struct udphdr *udp);
    static void dump_packet(unsigned char *buff,int len);
    static void help();
    static int iszero(char *a,int len);
    static int ip_atou(char *ipa,unsigned int *ip32);
    static int p_filter(struct ether_header *eth);
    static int find_ne(u_char *d);
    static void p_ne(struct ne *neptr);
    static void free_ne(struct ne *neptr);
    static void p_count(struct ether_header *eth);
    static int getif1(char *ifname,int i);
    static void p_table();
    static void endfun();
    static void solution();

//    struct cmd_flags{
//        static bool a;//arp和ip,其他
//        static bool e;//显示Ethernet报头
//        static bool d;//包的内容是以16进制整数和ASCII码来显示
//        static bool i;
//        static char ifname[IFRLEN];
//        static bool p;
//        static bool f;
//    };

//    struct print_out{//只在指定了-p时有用
//        static bool arp;
//        static bool ip;
//        static bool icmp;
//        static bool tcp;
//        static bool udp;
//    };

//    struct ne{
//        static u_char a[6];
//        static struct ne *next;
//    };

//    //统计
//    struct count{
//        //main
//        static time_t st;
//        static int mac_s;
//        static int mac_l;
//        static int macbyte;
//        static int mac;
//        //p_count
//        static int macbroad;

//        static int ipbroad;
//        static int ipbyte;
//        static int ip;
//        static int tcp;
//        static int udp;

//        static int icmp;
//        static int icmp_r;
//        static int icmp_d;
//    };

//    struct filter{
//        bool i;
//        bool p;
//        unsigned int ip;
//        int port;
//    };

//    struct cmd_flags f;
//    struct print_out p;
//    struct ne nenode;
//    struct count ct;
//    struct filter pf;
};
