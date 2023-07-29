#include"core.h"

#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/wait.h>

#define KEY1 101

unsigned int Core::submask;
string Core::res;
bool Core::stop;

string Core::start_time;
string Core::end_time;
string Core::mac_board;
string Core::mac_short;
string Core::mac_long;
string Core::mac_byte;
string Core::mac_packet;
string Core::bit_s;
string Core::mac_byte_speed;
string Core::mac_packet_speed;
string Core::ip_broadcast;
string Core::ip_byte;
string Core::ip_packet;
string Core::udp_packet;
string Core::tcp_packet;
string Core::icmp_packet;
string Core::icmp_redir;
string Core::icmp_des;

struct cmd_flags{
    bool a;//arp和ip,其他
    bool e;//显示Ethernet报头
    bool d;//包的内容是以16进制整数和ASCII码来显示
    bool i;
    char ifname[IFRLEN];
    bool p;
    bool f;
};

struct print_out{//只在指定了-p时有用
    bool arp;
    bool ip;
    bool icmp;
    bool tcp;
    bool udp;
};

struct ne{
    u_char a[6];
    struct ne *next;
};

//统计
struct count{
    //main
    time_t st;
    int mac_s;
    int mac_l;
    int macbyte;
    int mac;
    //p_count
    int macbroad;

    int ipbroad;
    int ipbyte;
    int ip;
    int tcp;
    int udp;

    int icmp;
    int icmp_r;
    int icmp_d;
};

struct filter{
    bool i;
    bool p;
    unsigned int ip;
    int port;
};

struct cmd_flags f;
struct print_out p;
struct ne nenode;
struct count ct;
struct filter pf;

//    struct share_memory* shared;

void Core::init(){
    f={false,false,false,false,false,false};//Core::
    p={false,false,false,false,false};
    nenode={0,0,0,0,0,0,NULL};
    ct={0,0,0,0,0,0,  0,0,0,0,0, 0,0,0};
    pf={false,false,0,0};

    Core::submask=0;
    Core::res="";
    Core::stop=false;

    Core::start_time="";
    Core::end_time="";
    Core::mac_board="";
    Core::mac_short="";
    Core::mac_long="";
    Core::mac_byte="";
    Core::mac_packet="";
    Core::bit_s="";
    Core::mac_byte_speed="";
    Core::mac_packet_speed="";
    Core::ip_broadcast="";
    Core::ip_byte="";
    Core::ip_packet="";
    Core::udp_packet="";
    Core::tcp_packet="";
    Core::icmp_packet="";
    Core::icmp_redir="";
    Core::icmp_des="";
}


void Core::print_ethernet(struct ether_header *eth){
    int type=ntohs(eth->ether_type);
    if(type<=1500){
        printf(" IEEE 802.3 Ethernet Frame:\n");
        Core::res+=" IEEE 802.3 Ethernet Frame:\n";
    }else{
        printf(" Ethernet Frame:\n");
        Core::res+=" Ethernet Frame:\n";
    }
    printf(" +----------------+----------------+----------------+\n");
    printf(" |Destination MAC Adress:%27s|\n",mac_ntoa(eth->ether_dhost));
    printf(" +----------------+----------------+----------------+\n");
    printf(" |Source MAC Adress:%32s|\n",mac_ntoa(eth->ether_shost));
    printf(" +----------------+----------------+----------------+\n");

    Core::res+=" +----------------+----------------+----------------+\n";
    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,50);
    sprintf(string," |Destination MAC Adress:%27s|\n",mac_ntoa(eth->ether_dhost));
    Core::res+=string;
    memset(string,0,50);
    Core::res+=" +----------------+----------------+----------------+\n";
    sprintf(string," |Source MAC Adress:%32s|\n",mac_ntoa(eth->ether_shost));
    Core::res+=string;
    memset(string,0,50);
    Core::res+=" +----------------+----------------+----------------+\n";

    if(type<=1500){
        printf(" |LenghL:%9u|\n",type);

        sprintf(string," |LenghL:%9u|\n",type);
        Core::res+=string;
        memset(string,0,50);
    }else{
        printf(" |E-Type:   0x%04x|\n",type);

        sprintf(string," |E-Type:   0x%04x|\n",type);
        Core::res+=string;
        memset(string,0,50);
    }

    printf(" +----------------+\n");
    Core::res+=" +----------------+\n";
}

char* Core::mac_ntoa(u_char *d){//将MAC地址变换为字符串的函数
    static char str[50];
    sprintf(str,"%02x:%02x:%02x:%02x:%02x:%02x",
        d[0],d[1],d[2],d[3],d[4],d[5]);
    return str;
}

void Core::print_arp(struct ether_arp *arp){
    static char *arp_operation[]={
        "(Undefine)",
        "(ARP Request)",
        "(ARP Reply)",
        "(RARP Requst)",
        "(RARP Reply)"
        };
    int op=ntohs(arp->ea_hdr.ar_op);
    if(op<=0||op>=5)
        op=0;
    printf(" Protocal:ARP\n");
    Core::res+=" Protocal:ARP\n";
    printf(" +--------+--------+--------+--------+\n");
    Core::res+=" +--------+--------+--------+--------+\n";

    printf(" |H-Ty:%2u%-10s|P:0x%04x%-9s|\n",
        ntohs(arp->ea_hdr.ar_hrd),
        (ntohs(arp->ea_hdr.ar_hrd)==ARPHRD_ETHER)?"(Ether)":"(Not Ether)",
        ntohs(arp->ea_hdr.ar_pro),
        (ntohs(arp->ea_hdr.ar_pro)==ETHERTYPE_IP)?"(IP)":"(Not IP)"
        );
    //printf("1\n");
    char* string=(char*)malloc(1024*1024*sizeof (char));
    //printf("2\n");
    memset(string,0,100);
    //printf("3\n");
    sprintf(string," |H-Ty:%2u%-10s|P:0x%04x%-9s|\n",
            ntohs(arp->ea_hdr.ar_hrd),
            (ntohs(arp->ea_hdr.ar_hrd)==ARPHRD_ETHER)?"(Ether)":"(Not Ether)",
            ntohs(arp->ea_hdr.ar_pro),
            (ntohs(arp->ea_hdr.ar_pro)==ETHERTYPE_IP)?"(IP)":"(Not IP)");
    //printf("4\n");
    Core::res+=string;
    //printf("5\n");
    memset(string,0,100);

    printf(" +--------+--------+--------+--------+\n");
    Core::res+=" +--------+--------+--------+--------+\n";

    printf(" |H-len:%2u|P-Len:%2u|op:%d%12s|\n",
        arp->ea_hdr.ar_hln,
        arp->ea_hdr.ar_pln,
        ntohs(arp->ea_hdr.ar_op),
        arp_operation[op]
        );
    sprintf(string," |H-len:%2u|P-Len:%2u|op:%d%12s|\n",
            arp->ea_hdr.ar_hln,
            arp->ea_hdr.ar_pln,
            ntohs(arp->ea_hdr.ar_op),
            arp_operation[op]);
    Core::res+=string;
    memset(string,0,100);

    printf(" +--------+--------+--------+--------+--------+--------+\n");
    printf(" |Source MAC Adress:%35s|\n",mac_ntoa(arp->arp_sha));
    printf(" +--------+--------+--------+--------+--------+--------+\n");
    printf(" |Source IP Address:%17s|\n",inet_ntoa(*(struct in_addr *)&arp->arp_spa));
    printf(" +--------+--------+--------+--------+--------+--------+\n");
    printf(" |Destination MAC Adress:%30s|\n",mac_ntoa(arp->arp_tha));
    printf(" +--------+--------+--------+--------+--------+--------+\n");
    printf(" |Dest   IP Address:%17s|\n",inet_ntoa(*(struct in_addr *)&arp->arp_tpa));
    printf(" +--------+--------+--------+--------+\n");

    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Source MAC Adress:%35s|\n",mac_ntoa(arp->arp_sha));

    char* source_mac_chars=(char*)malloc(sizeof (char)*100);
    sprintf(source_mac_chars,"%35s",mac_ntoa(arp->arp_sha));
    std::string source_mac_string=source_mac_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Source IP Address:%17s|\n",inet_ntoa(*(struct in_addr *)&arp->arp_spa));

    char* source_ip_chars=(char*)malloc(sizeof (char)*100);
    sprintf(source_ip_chars,"%17s",inet_ntoa(*(struct in_addr *)&arp->arp_spa));
    std::string source_ip_string=source_ip_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Destination MAC Adress:%30s|\n",mac_ntoa(arp->arp_tha));

    char* des_mac_chars=(char*)malloc(sizeof (char)*100);
    sprintf(des_mac_chars,"%30s",mac_ntoa(arp->arp_tha));
    std::string dest_mac_string=des_mac_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Dest   IP Address:%17s|\n",inet_ntoa(*(struct in_addr *)&arp->arp_tpa));

    char* des_ip_chars=(char*)malloc(sizeof (char)*100);
    sprintf(des_ip_chars,"%17s",inet_ntoa(*(struct in_addr *)&arp->arp_tpa));
    std::string dest_ip_string=des_ip_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";

    vector<std::string> data;
    data.push_back(STATE_RECEIVE);
    data.push_back(source_ip_string);
    data.push_back(source_mac_string);
    data.push_back(dest_ip_string);
    data.push_back(dest_mac_string);
    data.push_back(PROTOCOL_ARP);
    Data* temp=new Data(data);
    Data::datas.push_back(temp);
}

void Core::print_ip(struct ip *ip){
    printf(" Protocal:IP\n");
    printf(" +--------+--------+--------+--------+\n");
    printf(" |IV:%1u|HL:%02u|T:%8s|T-Length:%4u|\n",
        ip->ip_v,ip->ip_hl,ip_ttoa(ip->ip_tos),ntohs(ip->ip_len));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Identifier:%6u|FF:%3s|FO:%7u|\n",
        ntohs(ip->ip_id),ip_ftoa(ntohs(ip->ip_off)),ntohs(ip->ip_off)&IP_OFFMASK);
    printf(" +--------+--------+--------+--------+\n");
    printf(" |TTL:%4u|Pro:%4u|Checksum:%8u|\n",
        ip->ip_ttl,ip->ip_p,ntohs(ip->ip_sum));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Source IP Address:%17s|\n",
        inet_ntoa(*(struct in_addr *)&(ip->ip_src)));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Dest   IP Address:%17s|\n",
        inet_ntoa(*(struct in_addr *)&(ip->ip_dst)));
    printf(" +--------+--------+--------+--------+\n");

    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,100);
    Core::res+=" Protocal:IP\n";
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |IV:%1u|HL:%02u|T:%8s|T-Length:%4u|\n",
            ip->ip_v,ip->ip_hl,ip_ttoa(ip->ip_tos),ntohs(ip->ip_len));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Identifier:%6u|FF:%3s|FO:%7u|\n",
            ntohs(ip->ip_id),ip_ftoa(ntohs(ip->ip_off)),ntohs(ip->ip_off)&IP_OFFMASK);
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |TTL:%4u|Pro:%4u|Checksum:%8u|\n",
            ip->ip_ttl,ip->ip_p,ntohs(ip->ip_sum));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Source IP Address:%17s|\n",
            inet_ntoa(*(struct in_addr *)&(ip->ip_src)));

    char* src_ip_chars=(char*)malloc(sizeof (char)*100);
    sprintf(src_ip_chars,"%17s",inet_ntoa(*(struct in_addr *)&(ip->ip_src)));
    std::string source_ip_string=src_ip_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Dest   IP Address:%17s|\n",
            inet_ntoa(*(struct in_addr *)&(ip->ip_dst)));

    char* dest_ip_chars=(char*)malloc(sizeof (char)*100);
    sprintf(dest_ip_chars,"%17s",inet_ntoa(*(struct in_addr *)&(ip->ip_dst)));
    std::string dest_ip_string=dest_ip_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";

    vector<std::string> data;
    data.push_back(STATE_RECEIVE);
    data.push_back(source_ip_string);
    data.push_back("NULL");
    data.push_back(dest_ip_string);
    data.push_back("NULL");
    data.push_back(PROTOCOL_IP);
    Data* temp=new Data(data);
    Data::datas.push_back(temp);
}

char* Core::ip_ttoa(int flag){//将IP报头中的标志变换为ASCII码的辅助函数。
    static int f_it[]={'1','1','1','D','T','R','C','X'};
    static char str[17];
    u_int mask=0x80;
    int i;
    for(i=0;i<8;i++){
        if(((flag<<i)&mask)!=0)
            str[i]=f_it[i];
        else
            str[i]='0';
    }
    str[i]='\0';
    return str;
}

 char* Core::ip_ftoa(int flag){//将IP报头标志变换为ASCII码的辅助函数。
    static int f_if[]={'R','D','M'};
    static char str[17];
    u_int mask=0x8000;
    int i;
    for(i=0;i<3;i++){
        if(((flag<<i)&mask)!=0)
            str[i]=f_if[i];
        else
            str[i]='0';
    }
    str[i]='\0';
    return str;
}

 void Core::print_icmp(struct icmp *icmp){
    static char *type_name[]={
        "Echo Reply",//0
        "Undifine",//1
        "Undifine",//2
        "Destination Unreachable",//3
        "Source Quench",//4
        "Redirect",//5
        "Undifine",//6
        "Undifine",//7
        "Echo Request",//8
        "Router Advertisement",//9
        "Route Solicitation",//10
        "Time Exceeded",//11
        "Parameter Problem",//12
        "Timestamp Request*",//13
        "Timestamp Reply*",//14
        "Information Request*",//15
        "Information Reply*",//16
        "Address Mask Request",//17
        "Address Mask Reply",//18
        "Unknown"
        };
    int type=icmp->icmp_type;
    if(type<0||type>18)
        type=19;

    printf(" Protocal:ICMP(%s)\n",type_name[type]);
    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,100);
    sprintf(string," Protocal:ICMP(%s)\n",type_name[type]);
    Core::res+=string;
    memset(string,0,100);

    printf(" +--------+--------+--------+--------+\n");
    Core::res+=" +--------+--------+--------+--------+\n";

    printf(" |Type:%3u|Code:%3u|Checksum:%8u|\n",
        icmp->icmp_type,icmp->icmp_code,ntohs(icmp->icmp_cksum));
    sprintf(string," |Type:%3u|Code:%3u|Checksum:%8u|\n",
            icmp->icmp_type,icmp->icmp_code,ntohs(icmp->icmp_cksum));
    Core::res+=string;
    memset(string,0,100);

    printf(" +--------+--------+--------+--------+\n");
    Core::res+=" +--------+--------+--------+--------+\n";

    bool fl=false;
    if(type==0||type==8){
        printf(" |Identifi:%8u|Seq  Num:%8u|\n",
        ntohs(icmp->icmp_id),ntohs(icmp->icmp_seq));
        sprintf(string," |Identifi:%8u|Seq  Num:%8u|\n",
                ntohs(icmp->icmp_id),ntohs(icmp->icmp_seq));
        Core::res+=string;
        memset(string,0,100);
    }else if(type==3){
        if(icmp->icmp_code==4){
            printf(" |void:%5u|Next MTU:%5u|\n",
            ntohs(icmp->icmp_pmvoid),ntohs(icmp->icmp_nextmtu));
            sprintf(string," |void:%5u|Next MTU:%5u|\n",
                    ntohs(icmp->icmp_pmvoid),ntohs(icmp->icmp_nextmtu));
            Core::res+=string;
            memset(string,0,100);
        }else{
            printf(" |Unsed:%10lu|\n",
                (u_long)ntohl(icmp->icmp_void));
            sprintf(string," |Unsed:%10lu|\n",
                    (u_long)ntohl(icmp->icmp_void));
            Core::res+=string;
            memset(string,0,100);
        }

    }else if(type==5){
        printf(" |Router IP Address:%15s|\n",
            inet_ntoa(*(struct in_addr *)&(icmp->icmp_gwaddr)));
        sprintf(string," |Router IP Address:%15s|\n",
                inet_ntoa(*(struct in_addr *)&(icmp->icmp_gwaddr)));
        Core::res+=string;
        memset(string,0,100);
    }
    else if(type==11){
        printf(" |Unused:%10lu|\n",
            (u_long)ntohl(icmp->icmp_void));
        sprintf(string," |Unused:%10lu|\n",
                (u_long)ntohl(icmp->icmp_void));
        Core::res+=string;
        memset(string,0,100);
    }else{
        fl=true;
    }
    if(fl==false){
        printf(" +--------+--------+--------+--------+\n");
        Core::res+=" +--------+--------+--------+--------+\n";
    }
    if(type==3||type==5||type==11)
        print_ip((struct ip *)(((char *)icmp)+8));
}

 void Core::print_tcp(struct tcphdr *tcp){
    //每行32bit
    printf(" Protocol:TCP\n");
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Source Port:%5u|Dest Port:%7u|\n",
        ntohs(tcp->th_sport),ntohs(tcp->th_dport));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |sequnce Number:%20lu|\n",
        (u_long)ntohl(tcp->th_seq));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Acknowlegement Number:%13lu|\n",
        (u_long)ntohl(tcp->th_ack));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Do%3u|RR|F:%6s|Window Size:%5u|\n",
        tcp->th_off,tcp_ftoa(tcp->th_flags),ntohs(tcp->th_win));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Cheksum:%9u|Urgent-P:%8u|\n",
        ntohs(tcp->th_sum),ntohs(tcp->th_urp));
    printf(" +--------+--------+--------+--------+\n");

    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,100);
    Core::res+=" Protocol:TCP\n";
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Source Port:%5u|Dest Port:%7u|\n",
            ntohs(tcp->th_sport),ntohs(tcp->th_dport));

    char* source_port_chars=(char*)malloc(sizeof (char)*100);
    char* des_port_chars=(char*)malloc(sizeof (char)*100);
    sprintf(source_port_chars,"%5u",ntohs(tcp->th_sport));
    sprintf(des_port_chars,"%7u",ntohs(tcp->th_dport));
    std::string source_port=source_port_chars;
    std::string des_port=des_port_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |sequnce Number:%20lu|\n",
            (u_long)ntohl(tcp->th_seq));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Acknowlegement Number:%13lu|\n",
            (u_long)ntohl(tcp->th_ack));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Do%3u|RR|F:%6s|Window Size:%5u|\n",
            tcp->th_off,tcp_ftoa(tcp->th_flags),ntohs(tcp->th_win));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Cheksum:%9u|Urgent-P:%8u|\n",
            ntohs(tcp->th_sum),ntohs(tcp->th_urp));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";

    vector<std::string> data;
    data.push_back(STATE_RECEIVE);
    data.push_back("NULL");
    data.push_back(source_port);
    data.push_back("NULL");
    data.push_back(des_port);
    data.push_back(PROTOCOL_TCP);
    Data* temp=new Data(data);
    Data::datas.push_back(temp);
}

 char* Core::tcp_ftoa(int flag){//TCP报头中的标志变换为ASCII码的辅助函数。
    static int f_tf[]={'U','A','P','R','S','F'};
    static char str[17];
    u_int mask=1<<5;
    int i;
    for(i=0;i<6;i++){
        if(((flag<<i)&mask)!=0)
            str[i]=f_tf[i];
        else
            str[i]='0';
    }
    str[i]='\0';
    return str;
}

void Core::print_udp(struct udphdr *udp){
    //每行32bit
    printf(" Protocol:UDP\n");
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Source Port:%5u|Dest Port:%7u|\n",
        ntohs(udp->uh_sport),ntohs(udp->uh_dport));
    printf(" +--------+--------+--------+--------+\n");
    printf(" |Length:%10u|Checksum:%8u|\n",
        ntohs(udp->uh_ulen),ntohs(udp->uh_sum));
    printf(" +--------+--------+--------+--------+\n");

    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,100);
    Core::res+=" Protocol:UDP\n";
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Source Port:%5u|Dest Port:%7u|\n",
            ntohs(udp->uh_sport),ntohs(udp->uh_dport));

    char* source_port_chars=(char*)malloc(sizeof (char)*100);
    char* des_port_chars=(char*)malloc(sizeof (char)*100);
    sprintf(source_port_chars,"%5u",ntohs(udp->uh_sport));
    sprintf(des_port_chars,"%7u",ntohs(udp->uh_dport));
    std::string source_port=source_port_chars;
    std::string des_port=des_port_chars;

    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";
    sprintf(string," |Length:%10u|Checksum:%8u|\n",
            ntohs(udp->uh_ulen),ntohs(udp->uh_sum));
    Core::res+=string;
    memset(string,0,100);
    Core::res+=" +--------+--------+--------+--------+\n";

    vector<std::string> data;
    data.push_back(STATE_RECEIVE);
    data.push_back("NULL");
    data.push_back(source_port);
    data.push_back("NULL");
    data.push_back(des_port);
    data.push_back(PROTOCOL_UDP);
    Data* temp=new Data(data);
    Data::datas.push_back(temp);
}

void Core::dump_packet(unsigned char *buff,int len){
    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,100);
    int i,j;
    printf(" Frame Dump:\n");
    Core::res+=" Frame Dump:\n";
    for(i=0;i<len;i+=16){
        //16
        for(j=i;j<i+16&&j<len;j++){
            printf("%02x",buff[j]);
            sprintf(string,"%02x",buff[j]);
            Core::res+=string;
            memset(string,0,100);
            if(j%2==1){
                printf(" ");
                Core::res+=" ";
            }

        }
        if(j==len&&len%16!=0)
            for(j=0;j<40-(len%16)*2.5;j++){
                printf(" ");
                Core::res+=" ";
        }
        printf("    ");
        Core::res+="    ";
        //ASCII
        for(j=i;j<i+16&&j<len;j++){
            if((buff[j]>=0x20)&&(buff[j]<=0x7e)){
                putchar(buff[j]);
                sprintf(string,"%c",buff[j]);
                Core::res+=string;
                memset(string,0,100);
            }else{
                printf(".");
                Core::res+=".";
            }

        }
        printf("\n");
        Core::res+="\n";
        fflush(stdout);
    }
}

 void Core::help(){
    printf("usage: ./ipdump [-aedht] [-p protocols] [-i ifrname] [-f filters]\n");
    printf("protocols: arp ip icmp tcp udp \n");//other??
    printf("filters: ip <IP address> port <PORT number>\n");
    printf("default: ./ipdump -p arp ip icmp tcp udp\n");

    Core::res=Core::res+"usage: ./ipdump [-aedht] [-p protocols] [-i ifrname] [-f filters]\n";
    Core::res=Core::res+"protocols: arp ip icmp tcp udp \n";
    Core::res=Core::res+"filters: ip <IP address> port <PORT number>\n";
    Core::res=Core::res+"default: ./ipdump -p arp ip icmp tcp udp\n";

    //printf("console: %s\n",Core::res.c_str());
}

int Core::iszero(char *a,int len){
    for(int i=0;i<len;i++){
        if(a[i]!='0')
            return -1;
    }
    return 0;
}

int Core::ip_atou(char *ipa,unsigned int *ip32){
    //u_char *ip=(u_char *)ip32;
    *ip32=0;
    unsigned int ret=0;
    if(strlen(ipa)<7||strlen(ipa)>15)//0.0.0.0 255.255.255.255
        return 1;
    char *temp=strtok(ipa,".");
    if(temp==NULL||atoi(temp)>255||atoi(temp)<0)
        return 1;
    if(atoi(temp)==0){
        if(iszero(temp,strlen(temp))==-1)
            return 1;
    }
    //*ip32=*ip32<<8+(unsigned int)atoi(temp);
    *ip32=(*ip32)*256+(unsigned int)atoi(temp);
    //printf("test\n");
    //printf("%u\n",*ip32);
    for(int i=0;i<3;i++){
        temp=strtok(NULL,".");
        if(temp==NULL||atoi(temp)>255||atoi(temp)<0)
            return 1;
        if(atoi(temp)==0){
            if(iszero(temp,strlen(temp))==-1)
                return 1;
        }
        //*ip32=*ip32<<8+(unsigned int)atoi(temp);
        *ip32=(*ip32)*256+(unsigned int)atoi(temp);
    }
    return 0;
}

 int Core::p_filter(struct ether_header *eth){//0则进一部处理，1则不处理
    char *ptr=(char *)eth;
    ptr=ptr+sizeof(struct ether_header);
    struct ip *ip;
    struct tcphdr *tcp;
    struct udphdr *udp;
    if(ntohs(eth->ether_type)==ETHERTYPE_IP){
        ip=(struct ip *)ptr;
        if(pf.i==true){
            //printf("pf.ip:%u\n",pf.ip);
            //printf("ip->ip_src.s_addr:%u\n",ip->ip_src.s_addr);
            //printf("ntohl(ip->ip_src.s_addr):%u\n",ntohl(ip->ip_src.s_addr));
            //if(pf.ip!=ip->ip_src.s_addr&&pf.ip!=ip->ip_dst.s_addr){
            if(pf.ip!=ntohl(ip->ip_src.s_addr)&&pf.ip!=ntohl(ip->ip_dst.s_addr)){
                return 1;
            }else if(pf.port==false){
                return 0;
            }
        }
        ptr=ptr+((int)(ip->ip_hl)<<2);
        switch(ip->ip_p){
            case IPPROTO_TCP://TCP匹配
                tcp=(struct tcphdr *)ptr;
                if(ntohs(tcp->th_sport)==pf.port||ntohs(tcp->th_dport)==pf.port)
                    return 0;
                break;
            case IPPROTO_UDP://UDP匹配
                udp=(struct udphdr *)ptr;
                if(ntohs(udp->uh_sport)==pf.port||ntohs(udp->uh_dport)==pf.port)
                    return 0;
                break;
        }
    }
    return 1;
}

 int Core::find_ne(u_char *d){
    struct ne* neptr=&nenode;
    while(neptr->next!=NULL){
        if(neptr->a[0]==d[0]&&neptr->a[1]==d[1]&&neptr->a[2]==d[2]&&neptr->a[3]==d[3]&&neptr->a[4]==d[4]&&neptr->a[5]==d[5])
            return 1;
        else
            neptr=neptr->next;
    }
    for(int i=0;i<6;i++){
        neptr->a[i]=d[i];
    }
    neptr->next=(struct ne*)malloc(sizeof(struct ne));
    neptr=neptr->next;
    neptr->next=NULL;
    return 0;
}

 void Core::p_ne(struct ne *neptr){
     char* string=(char*)malloc(1024*1024*sizeof (char));
     memset(string,0,100);
    printf("\n	Find these mac address:\n");
    Core::res+="\n	Find these mac address:\n";
    while(neptr->next!=NULL){//nenode.next的值是否为空，判断对于数组a[]是否有效
        printf("	%s\n",mac_ntoa(neptr->a));
        sprintf(string,"	%s\n",mac_ntoa(neptr->a));
        Core::res+=string;
        memset(string,0,100);
        neptr=neptr->next;
    }
}

 void Core::free_ne(struct ne *neptr){
    struct ne *neptr0;
    while(neptr!=NULL){
        neptr0=neptr;
        neptr=neptr->next;
        free(neptr0);
    }
}

void Core::p_count(struct ether_header *eth){
    int i;
    for(i=0;i<6;i++){
        if(eth->ether_dhost[0]!=0xff)
            break;
    }
    if(i==6){
         ct.macbroad++;
    }
    char *ptr=(char *)eth;
    ptr=ptr+sizeof(struct ether_header);
    struct ip *ip;
    struct icmp *icmp;
    struct udphdr *udp;
    if(ntohs(eth->ether_type)==ETHERTYPE_IP){
        ct.ip++;
        ip=(struct ip *)ptr;
        ct.ipbyte+=ntohs(ip->ip_len)-ip->ip_hl*4;
        if((ntohl(ip->ip_dst.s_addr)|Core::submask)==0xFFFFFFFF)//目的地址后面全1
            ct.ipbroad++;
        switch(ip->ip_p){
            case IPPROTO_TCP://TCP匹配
                ct.tcp++;
                break;
            case IPPROTO_UDP://UDP匹配
                ct.udp++;
                break;
            case IPPROTO_ICMP://ICMP匹配
                ct.icmp++;
                icmp=(struct icmp *)ptr;
                if(icmp->icmp_type==3)
                    ct.icmp_d++;
                if(icmp->icmp_type==5)
                    ct.icmp_r++;
                break;
        }
    }
}

int Core::getif1(char *ifname,int i) {
    char bad_if[6][6]= {"lo:","lo","stf","gif","dummy","vmnet"};
    struct if_nameindex* ifn=if_nameindex();
    if(ifn == NULL) {
        return -1;
    }
    for(int j=0;j<6;j++){
        if (strcmp(ifn[i].if_name,bad_if[j]) == 0){
            i++;
            if(ifn[i].if_index==0){
                if_freenameindex(ifn);
                return -1;
            }
            j=0;
        }
    }
    strcpy(ifname,ifn[i].if_name);
    if_freenameindex(ifn);
    return i;
}

void Core::p_table(){
    time_t et;
    time(&et);
    printf("\n\n");
    printf("	The statistical  information\n");
    printf("	varibale	 values\n");
    printf("	StartTime	 %s",ctime(&ct.st));
    printf("	EndTime		 %s",ctime(&et));
    printf("	MAC Broad	 %d\n",ct.macbroad);
    printf("	MAC Short	 %d\n",ct.mac_s);
    printf("	MAC Long	 %d\n",ct.mac_l);
    printf("	MAC Byte	 %d\n",ct.macbyte);
    printf("	MAC Packet	 %d\n",ct.mac);
    printf("	Bit/s		 %d\n",ct.macbyte/(int)(et-ct.st)*8);
    printf("	MAC ByteSpeed	 %d\n",ct.macbyte/(int)(et-ct.st));
    printf("	MAC PacketSpeed  %d\n",ct.mac/(int)(et-ct.st));
    printf("	IP Broadcast	 %d\n",ct.ipbroad);
    printf("	IP Byte		 %d\n",ct.ipbyte);
    printf("	IP Packet	 %d\n",ct.ip);
    printf("	UDP Packet	 %d\n",ct.udp);
    printf("	TCP Packet	 %d\n",ct.tcp);
    printf("	ICMP Packet	 %d\n",ct.icmp);
    printf("	ICMP Redirect	 %d\n",ct.icmp_r);
    printf("	ICMP Destination %d\n",ct.icmp_d);

    char* string=(char*)malloc(1024*1024*sizeof (char));
    memset(string,0,100);

    sprintf(string,"%s",ctime(&ct.st));
    Core::start_time=string;
    memset(string,0,100);

    sprintf(string,"%s",ctime(&et));
    Core::end_time=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.macbroad);
    Core::mac_board=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.mac_s);
    Core::mac_short=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.mac_l);
    Core::mac_long=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.macbyte);
    Core::mac_byte=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.mac);
    Core::mac_packet=string;
    memset(string,0,100);

    //
    sprintf(string,"%d\n",ct.macbyte/(int)(et-ct.st)*8);
    Core::bit_s=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.macbyte/(int)(et-ct.st));
    Core::mac_byte_speed=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.mac/(int)(et-ct.st));
    Core::mac_packet_speed=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.ipbroad);
    Core::ip_broadcast=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.ipbyte);
    Core::ip_byte=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.ip);
    Core::ip_packet=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.udp);
    Core::udp_packet=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.tcp);
    Core::tcp_packet=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.icmp);
    Core::icmp_packet=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.icmp_r);
    Core::icmp_redir=string;
    memset(string,0,100);

    sprintf(string,"%d\n",ct.icmp_d);
    Core::icmp_des=string;
    memset(string,0,100);
}

void Core::endfun(){
    //统计
    p_table();
    //网元
    p_ne(&nenode);
    free_ne(nenode.next);
}

void Core::solution(){

    //信号
    //signal(SIGINT,endfun);
    int s;
    if((s=socket(PF_PACKET,SOCK_PACKET,htons(ETH_P_ALL)))<0){
        perror(" socket");
        exit(1);
    }
    //未指定网口,获取网口名
    struct ifreq ifr_mask;
    char ifname[20];
    unsigned int* intptr;
    int ret=0;
    if(f.i==false){//get first ifname that has a submask//统计
        while(1){
            if((ret=Core::getif1(ifname,ret))==-1){
                printf("can\'t get a network interface name that has a submask");
                exit(1);
            }
            memset(&ifr_mask, 0, sizeof(ifr_mask));
            strcpy(ifr_mask.ifr_name,ifname);
            if(ioctl(s,SIOCGIFNETMASK,&ifr_mask)< 0){
                ret++;
                continue;
            }else{
                printf("Listen to the network interface:%s\n",ifname);
                intptr=(unsigned int*)&(ifr_mask.ifr_netmask);//int 32bit
                Core::submask=intptr[1];
                break;
            }
        }

    }// if no iframe,get the iframe
    //指定网口//
    struct ifreq interface;
    if(f.i==true){
        memset(&interface, 0, sizeof(interface));
        strncpy(interface.ifr_ifrn.ifrn_name,f.ifname,strlen(f.ifname));
        if(setsockopt(s,SOL_SOCKET,SO_BINDTODEVICE,(char *)&interface,sizeof(interface))<0){
            printf("network interface %s bind failed\n",f.ifname);
            exit(1);
        }
        if(ioctl(s,SIOCGIFNETMASK,&interface)< 0){
            printf("get submask failed\n");
            exit(1);
        }
        printf("Listen to the network interface:%s\n",f.ifname);
        intptr=(unsigned int*)&(interface.ifr_netmask);//int 32bit
        Core::submask=intptr[1];
    }
    //抓包处理
    int len;
    char *ptr0;//指针
    char *ptr;//指针
    unsigned char buff[MAXSIZE];

    struct ether_header *eth;
    struct ether_arp *arp;
    struct ip *ip;
    struct icmp *icmp;
    struct tcphdr *tcp;
    struct udphdr *udp;

    time(&ct.st);//设置开始时间
    int pack_num=1;
    while(!Core::stop){
        if((len=read(s,(char*)buff,MAXSIZE))<0){
            perror(" read");
            exit(1);
        }

        ptr=ptr0=(char*)buff;
        //以太包匹配
        eth=(struct ether_header *)ptr;
        //统计
        ct.mac++;
        ct.macbyte+=len;
        if(len<64)
            ct.mac_s++;
        else if(len>1518)
            ct.mac_l++;
        Core::p_count(eth);
        //网元发现
        Core::find_ne(eth->ether_dhost);
        Core::find_ne(eth->ether_shost);
        //过滤
        if(f.f==true){
            if(Core::p_filter(eth)==1)
                continue;
        }

        //显示
        //print(1);//gcc -o testip2 test.c
        //sudo ./testip2 -p arp
        ptr=ptr+sizeof(struct ether_header);
        if(ntohs(eth->ether_type)==ETHERTYPE_ARP){//ARP
            if(f.p==false||p.arp==true||f.a==true){//?????f.p==false||p.arp==true
                //print(3);
                printf("\n\n Packet Number:%d\n",pack_num++);
                if(f.e==true){
                    Core::print_ethernet(eth);
                }
                arp=(struct ether_arp*)ptr;//ARP匹配
                Core::print_arp(arp);
            }
            QThread::sleep(2);
        }else if(ntohs(eth->ether_type)==ETHERTYPE_IP){//IP ?????
            ip=(struct ip *)ptr;//ip匹配
            ptr=ptr+((int)(ip->ip_hl)<<2);//ip首部长乘4(Byte/char)
            // printf("\n\n Packet Number:%d\n",pack_num++);
            if(p.ip==true&&p.tcp==false&&p.udp==false&&p.icmp==false){
                if(f.e==true){
                    Core::print_ethernet(eth);
                }
                Core::print_ip(ip);
            }
            printf("\n ip_protocol_value: %d\n",ip->ip_p);
            switch(ip->ip_p){
                case IPPROTO_TCP://6
                    if(p.tcp==true||f.a==true||f.p==false){
                        printf("\nPacket Number:%d\n",pack_num++);
                        //print(2);
                        tcp=(struct tcphdr*)ptr;
                        ptr=ptr+((int)(tcp->th_off)<<2);
                        if(p.tcp==true||f.a==true||f.p==false){
                            if(p.ip||f.a==true||f.p==false){
                                if(f.e){
                                    Core::print_ethernet(eth);
                                }
                                Core::print_ip(ip);
                            }
                            Core::print_tcp(tcp);
                        }
                        if(f.d){
                            Core::dump_packet((unsigned char*)ptr0,len);
                            printf("\n");
                        }
                        QThread::sleep(2);
                    }
                    break;
                case IPPROTO_UDP://17
                    if(p.udp==true||f.a==true||f.p==false){
                        printf("\nPacket Number:%d\n",pack_num++);

                        udp=(struct udphdr*)ptr;
                        ptr=ptr+sizeof(struct udphdr);
                        if(p.udp||f.a==true||f.p==false){
                            if(p.ip||f.a==true||f.p==false){
                                if(f.e){
                                    Core::print_ethernet(eth);
                                }
                                Core::print_ip(ip);
                            }
                            Core::print_udp(udp);
                        }
                        if(f.d){
                            Core::dump_packet((unsigned char*)ptr0,len);
                            printf("\n");
                        }
                        QThread::sleep(2);
                    }
                    break;

                case IPPROTO_ICMP://1
                    if(p.icmp==true||f.a==true||f.p==false){
                        printf("\nPacket Number:%d\n",pack_num++);

                        icmp=(struct icmp*)ptr;
                        ptr=ptr+sizeof(struct udphdr);
                        if(p.icmp||f.a==true||f.p==false){
                            if(p.ip||f.a==true||f.p==false){
                                if(f.e){
                                    Core::print_ethernet(eth);
                                }
                                Core::print_ip(ip);
                            }
                            Core::print_icmp(icmp);
                        }
                        if(f.d){
                            Core::dump_packet((unsigned char*)ptr0,len);
                            printf("\n");
                        }
                        QThread::sleep(2);
                    }
                    break;
                default:
                    printf(" Protocol : unknown\n");
                    if(f.d){
                        Core::dump_packet((unsigned char*)ptr0,len);
                        printf("\n");
                    }
                    QThread::sleep(2);
                    break;
            }
        }else if(f.a){//以太其他
            if(f.e==true){
                printf("\n\n Packet Number:%d\n",pack_num++);
                Core::print_ethernet(eth);
            }
            printf(" protocol:unknown\n");
            QThread::sleep(2);
        }

        //ui->te_res->setText(QString::fromStdString(Core::res));
    }
}


