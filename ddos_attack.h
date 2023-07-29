#ifndef DDOS_ATTACK_H
#define DDOS_ATTACK_H

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <stdlib.h>
#include<vector>
#include<iostream>
#include<string>
#include<string.h>
using namespace std;

#define DEFAULT_IP "192.168.176.134"  // win10
#define DEFAULT_PORT 80
#define DEFAULT_TIME_STEP 2

class DDOS_Attack{
public:
    static int countOfPacket;
    static bool sending;
    static int destination_port;
    static char* destination_ip;
    static int flagRst;
    static int flagSyn;
    static string ddos_log;

    static void init();
    static int random_Port(void);// random number for port spoofing(0-65535)
    static int random_For_Ip(void);// random number for IP spoofing(0-255)
    static char *get_random_Ip();
    static int valid_Ip(char *ip);
    static void stop_attack_Handler();
    static unsigned short checksum(unsigned short *ptr, int nbytes);
    static void solution(char* destination_ip,int destination_port,bool sign);
};

#endif // DDOS_ATTACK_H
