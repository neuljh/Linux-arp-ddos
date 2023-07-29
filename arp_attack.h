#ifndef ARP_ATTACK_H
#define ARP_ATTACK_H


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <getopt.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netpacket/packet.h>
//1


#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <errno.h>
//2

#include<vector>
#include<iostream>
#include<string>
#include<string.h>
using namespace std;

#define DEFAULT_TIME_STEP 2//attack interval time
#define MAX_LINE 1024//data max length

class ARP_attack{
public:
    static int get_default_config();
    static void get_arp_table();
    static void init();
    static void get_arp_dump(unsigned char *buff,int len);

    static vector<string> network_interface_all;//all interface
    static vector<string> local_ip_all;
    static vector<string> local_mac_all;

    static vector<string> contents;//arp table contents
    static vector<string> ips;
    static vector<string> hw_type;
    static vector<string> flags;
    static vector<string> hw_address;
    static vector<string> masks;
    static vector<string> devices;

    static uint8_t infinite_loop;//symbol of infinite loop
    static string log;
    static int attack_times;
    static string arp_dump;
};




#endif // ARP_ATTACK_H


