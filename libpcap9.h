#ifndef LIBPCAP9_H
#define LIBPCAP9_H

#endif // LIBPCAP9_H
#include<string>
#include<vector>
using namespace std;

class libpcap9{
public:
    static int number;
    //ethernet
    static vector<string> ethernet_type;
    static vector<string> mac_source;
    static vector<string> mac_des;
     //ethernet
     //arp
    static vector<unsigned short> hardware_type;
    static vector<unsigned short> protocol_type;
    static vector<unsigned char> hardware_length;
    static vector<unsigned char> protocol_length;
    static vector<unsigned short> operation_code;
    static vector<string> protocol;
    static vector<string> eth_source;
    static vector<string> ip_source;
    static vector<string> eth_des;
    static vector<string> ip_des;
    //arp
    //ip
    static vector<unsigned char> ip_version;
    static vector<int> ip_header_length;
    static vector<unsigned char> ip_tos;
    static vector<unsigned short> ip_total_length;
    static vector<unsigned short> ip_id;
    static vector<unsigned int> ip_offset;
    static vector<int> ip_ttl;
    static vector<unsigned char> ip_protocol;
    static vector<int> ip_checksum;
    static vector<string> ip_source_address;
    static vector<string> ip_des_adddress;
    //ip
    //tcp
    static vector<int> tcp_source_port;
    static vector<int> tcp_des_port;
    static vector<string> tcp_protocol;
    static vector<unsigned int> tcp_seq_num;
    static vector<unsigned int> tcp_ack_num;
    static vector<int> tcp_header_length;
    static vector<int> tcp_reserved;
    static vector<string> tcp_flags;
    static vector<int> tcp_win_size;
    static vector<int> tcp_checksum;
    static vector<int> tcp_u_pointer;
    //tcp
    //udp
    static vector<int> udp_source_port;
    static vector<int> udp_des_port;
    static vector<string> udp_service;
    static vector<int> udp_length;
    static vector<int> udp_checksum;
    //udp
    //icmp
    static vector<int> icmp_type;
    static vector<string> icmp_protocol;
    static vector<int> icmp_code;

    static vector<int> icmp_seq_num;
    static vector<int> icmp_checksum;

    static vector<int> icmp_ids;
    //icmp

    static string get_address(string result,unsigned char s[] );
    static void tcp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    static void udp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    static void icmp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    static void arp_protocol_packet_callback(u_char* argument,
        const struct pcap_pkthdr* packet_header,
        const u_char* packet_content);
    static void ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    static void ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content);
    static void adjust();
    static void solution();
};

