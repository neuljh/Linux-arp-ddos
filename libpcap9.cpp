#include<pcap.h>
#include<string>
#include<string.h>
#include<iostream>
#include<ctime>
#include <arpa/inet.h>
#include"libpcap9.h"

using namespace std;
int state;

int libpcap9::number;
//ethernet
vector<string> libpcap9::ethernet_type;
vector<string> libpcap9::mac_source;
vector<string> libpcap9::mac_des;
 //ethernet
 //arp
vector<unsigned short> libpcap9::hardware_type;
vector<unsigned short> libpcap9::protocol_type;
vector<unsigned char> libpcap9::hardware_length;
vector<unsigned char> libpcap9::protocol_length;
vector<unsigned short> libpcap9::operation_code;
vector<string> libpcap9::protocol;
vector<string> libpcap9::eth_source;
vector<string> libpcap9::ip_source;
 vector<string> libpcap9::eth_des;
vector<string> libpcap9::ip_des;
//arp
//ip
vector<unsigned char> libpcap9::ip_version;
 vector<int> libpcap9::ip_header_length;
 vector<unsigned char> libpcap9::ip_tos;
vector<unsigned short> libpcap9::ip_total_length;
vector<unsigned short> libpcap9::ip_id;
vector<unsigned int> libpcap9::ip_offset;
 vector<int> libpcap9::ip_ttl;
 vector<unsigned char> libpcap9::ip_protocol;
 vector<int> libpcap9::ip_checksum;
 vector<string> libpcap9::ip_source_address;
 vector<string> libpcap9::ip_des_adddress;
//ip
//tcp
 vector<int> libpcap9::tcp_source_port;
 vector<int> libpcap9::tcp_des_port;
 vector<string> libpcap9::tcp_protocol;
 vector<unsigned int> libpcap9::tcp_seq_num;
 vector<unsigned int> libpcap9::tcp_ack_num;
 vector<int> libpcap9::tcp_header_length;
 vector<int> libpcap9::tcp_reserved;
 vector<string> libpcap9::tcp_flags;
 vector<int> libpcap9::tcp_win_size;
 vector<int> libpcap9::tcp_checksum;
 vector<int> libpcap9::tcp_u_pointer;
//tcp
//udp
 vector<int> libpcap9::udp_source_port;
 vector<int> libpcap9::udp_des_port;
 vector<string> libpcap9::udp_service;
 vector<int> libpcap9::udp_length;
 vector<int> libpcap9::udp_checksum;
//udp
//icmp
 vector<int> libpcap9::icmp_type;
 vector<string> libpcap9::icmp_protocol;
 vector<int> libpcap9::icmp_code;
 vector<int> libpcap9::icmp_ids;
 vector<int> libpcap9::icmp_seq_num;
 vector<int> libpcap9::icmp_checksum;
//icmp

// //以太网协议
// struct ether_header {
//     u_int8_t ether_dhost[6]; //目的以太网地址
//     u_int8_t ether_shost[6]; //源以太网地址
//     u_int16_t ether_type; //以太网类型
// };

 //IP地址格式
 typedef u_int32_t in_addr_t;
 //struct  in_addr
 //{
 //	in_addr_t s_addr; //存放IP地址
 //};

 //ARP协议
 struct arp_header
 {
     u_int16_t arp_hardware_type;
     u_int16_t arp_potocol_type;
     u_int8_t arp_hardware_length;
     u_int8_t arp_protocol_length;
     u_int16_t arp_operation_code;
     u_int8_t arp_source_ethernet_address[6];
     u_int8_t arp_source_ip_address[4];
     u_int8_t arp_destination_ethernet_address[6];
     u_int8_t arp_destination_ip_address[4];
 };

 //IP协议
 struct ip_header {
 #ifdef WORDS_BIGENDIAN
     u_int8_t ip_version : 4, ip_header_length : 4;

 #else
     u_int8_t ip_header_length : 4, ip_version : 4;

 #endif
     u_int8_t ip_tos;
     u_int16_t ip_length;
     u_int16_t ip_id;
     u_int16_t ip_off;
     u_int8_t ip_ttl;
     u_int8_t ip_protocol;
     u_int16_t ip_checksum;
     struct in_addr ip_source_address;
     struct in_addr ip_destination_address;
 };

 //UDP协议
 struct udp_header
 {
     u_int16_t udp_source_port;
     u_int16_t udp_destination_port;
     u_int16_t udp_length;
     u_int16_t udp_checksum;
 };

 //TCP协议
 struct tcp_header {
     u_int16_t tcp_source_port;
     u_int16_t tcp_destination_port;
     u_int32_t tcp_acknowledgement;
     u_int32_t tcp_ack;

 #ifdef WORDS_BIGENDIAN
     u_int8_t tcp_offset : 4, tcp_reserved : 4;

 #else
     u_int8_t tcp_offset : 4, tcp_reserved : 4;

 #endif
     u_int8_t tcp_flags;
     u_int16_t tcp_windows;
     u_int16_t tcp_checksum;
     u_int16_t tcp_urgent_pointer;
 };

 //ICMP协议
 struct icmp_header
 {
     u_int8_t icmp_type;
     u_int8_t icmp_code;
     u_int16_t icmp_checksum;
     u_int16_t icmp_id_lliiuuwweennttaaoo;
     u_int16_t icmp_sequence;
 };



     string libpcap9::get_address(string result,unsigned char s[] ){
         for (int i=0;i<6;i++) {
             char temp[6];
             sprintf(temp, "%02x", s[i]);
             string res=temp;
             result=result+res;
             if(i!=5){
                 result=result+":";
             }
         }
         return result;
     }




     void libpcap9::tcp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
        struct tcp_header* tcp_protocol;
        u_char flags;
        int header_length;
        u_short source_port;
        u_short destination_port;
        u_short windows;
        u_short urgent_pointer;
        u_int sequence;
        u_int acknowledgement;
        u_int16_t checksum;
        tcp_protocol = (struct tcp_header*)(packet_content + 14 + 20);

        source_port = ntohs(tcp_protocol->tcp_source_port);
        destination_port = ntohs(tcp_protocol->tcp_destination_port);
        header_length = tcp_protocol->tcp_offset * 4;
        sequence = ntohl(tcp_protocol->tcp_acknowledgement);
        acknowledgement = ntohl(tcp_protocol->tcp_ack);
        windows = ntohs(tcp_protocol->tcp_windows);
        urgent_pointer = ntohs(tcp_protocol->tcp_urgent_pointer);
        flags = tcp_protocol->tcp_flags;
        checksum = ntohs(tcp_protocol->tcp_checksum);

        printf("------------- TCP Protocol(Transport Layer) -----------------\n");
        printf("Source Port: %d\n", source_port);
        printf("Destination Port: %d\n", destination_port);

        string tcp_protocol_string="0";

        switch (destination_port) {
        case 80:
            printf("HTTP protocol\n");
            tcp_protocol_string="HTTP protocol";
            break;
        case 21:
            printf("FTP protocol\n");
            tcp_protocol_string="FTP protocol";
            break;
        case 23:
            printf("TELNET protocol\n");
            tcp_protocol_string="TELNET protocol";
            break;
        case 25:
            printf("SMTP protocol\n");
            tcp_protocol_string="SMTP protocol";
            break;
        case 110:
            printf("POP3 protocol\n");
            tcp_protocol_string="POP3 protocol";
            break;
        }
        printf("Sequence number: %u\n", sequence);
        printf("Acknowledgement number: %u\n", acknowledgement);
        printf("Header length: %d\n", header_length);
        printf("Reserved: %d\n", tcp_protocol->tcp_reserved);



        string flags_string;
        printf("Flags: ");
        if (flags & 0x08) {
            printf("PSH");
            flags_string="PSH";
        }
        if (flags & 0x10) {
            printf("ACK");
            flags_string="ACK";
        }
        if (flags & 0x02) {
            printf("SYN");
            flags_string="SYN";
        }
        if (flags & 0x20) {
            printf("URG");
            flags_string="URG";
        }
        if (flags & 0x01) {
            printf("FIN");
            flags_string="FIN";
        }
        if (flags & 0x04) {
            printf("RST");
            flags_string="RST";
        }


        printf("\n");
        printf("Window Size: %d\n", windows);
        printf("Checksum: %d\n", checksum);
        printf("Urgent pointer: %d\n", urgent_pointer);

        libpcap9::tcp_source_port.push_back(source_port);
        libpcap9::tcp_des_port.push_back(destination_port);
        libpcap9::tcp_protocol.push_back(tcp_protocol_string);
        libpcap9::tcp_seq_num.push_back(sequence);
        libpcap9::tcp_ack_num.push_back(acknowledgement);
        libpcap9::tcp_header_length.push_back(header_length);
        libpcap9::tcp_reserved.push_back(tcp_protocol->tcp_reserved);
        libpcap9::tcp_flags.push_back(flags_string);
        libpcap9::tcp_win_size.push_back(windows);
        libpcap9::tcp_checksum.push_back(checksum);
        libpcap9::tcp_u_pointer.push_back(urgent_pointer);//tcp



    }

    void libpcap9::udp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
        struct udp_header* udp_protocol;
        u_short source_port;
        u_short destination_port;
        u_short length;
        udp_protocol = (struct udp_header*)(packet_content + 14 + 20);

        source_port = ntohs(udp_protocol->udp_source_port);
        destination_port = ntohs(udp_protocol->udp_destination_port);
        length = ntohs(udp_protocol->udp_length);

        printf("------------- UDP Protocol(Transport Layer) -----------------\n");
        printf("Source port:%d\n", source_port);
        printf("Destination port:%d\n", destination_port);

        string service_string;
        switch (destination_port) {
        case 138:
            printf("NETBIOS Datagram Service\n");
            service_string="NETBIOS Datagram Service";
            break;
        case 137:
            printf("NETBIOS Name Service\n");
            service_string="NETBIOS Name Service";
            break;
        case 139:
            printf("NETBIOS session service\n");
            service_string="NETBIOS session service";
            break;
        case 53:
            printf("name-domain service\n");
            service_string="name-domain service";
            break;
        default:
            break;
        }
        printf("Length: %d\n", length);
        printf("Checksum:%d\n", ntohs(udp_protocol->udp_checksum));

        libpcap9::udp_source_port.push_back(source_port);
        libpcap9::udp_des_port.push_back(destination_port);
        libpcap9::udp_service.push_back(service_string);
        libpcap9::udp_length.push_back(length);
        libpcap9::udp_checksum.push_back(ntohs(udp_protocol->udp_checksum));//udp

    }

    void libpcap9::icmp_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
        struct icmp_header* icmp_protocol;
        icmp_protocol = (struct icmp_header*)(packet_content + 14 + 20);
        printf("------------- ICMP Protocol(Transport Layer) -----------------\n");
        printf("ICMP Type: %d\n", icmp_protocol->icmp_type);
        string icmp_pro;
        switch (icmp_protocol->icmp_type) {
        case 8:
            printf("ICMP Echo Request Protocol\n");
            icmp_pro="ICMP Echo Request Protocol";
            printf("ICMP Code: %d\n", icmp_protocol->icmp_code);
            printf("Identifier: %d\n", icmp_protocol->icmp_id_lliiuuwweennttaaoo);
            printf("Sequence Number: %d\n", icmp_protocol->icmp_sequence);
            break;
        case 0:
            printf("ICMP Echo Reply Protocol\n");
            icmp_pro="ICMP Echo Reply Protocol";
            printf("ICMP Code: %d\n", icmp_protocol->icmp_code);
            printf("Identifier: %d\n", icmp_protocol->icmp_id_lliiuuwweennttaaoo);
            printf("Sequence Number: %d\n", icmp_protocol->icmp_sequence);
            break;
        default:
            break;
        }
        printf("ICMP Checksum: %d\n", icmp_protocol->icmp_checksum);

        libpcap9::icmp_type.push_back(icmp_protocol->icmp_type);
        libpcap9::icmp_protocol.push_back(icmp_pro);
        libpcap9::icmp_code.push_back(icmp_protocol->icmp_code);
        libpcap9::icmp_ids.push_back(icmp_protocol->icmp_id_lliiuuwweennttaaoo);
        libpcap9::icmp_seq_num.push_back(icmp_protocol->icmp_sequence);
        libpcap9::icmp_checksum.push_back(icmp_protocol->icmp_checksum);//icmp

    }

    void libpcap9::arp_protocol_packet_callback(u_char* argument,
        const struct pcap_pkthdr* packet_header,
        const u_char* packet_content)
    {
        struct arp_header* arp_protocol;
        u_short protocol_type;
        u_short hardware_type;
        u_short operation_code;
        u_char* mac_string;
        struct in_addr source_ip_address;
        struct in_addr destination_ip_address;
        u_char hardware_length;
        u_char protocol_length;

        printf("ARP Protocol\n");
        arp_protocol = (struct arp_header*)(packet_content + 14);
        hardware_type = ntohs(arp_protocol->arp_hardware_type);
        protocol_type = ntohs(arp_protocol->arp_potocol_type);
        operation_code = ntohs(arp_protocol->arp_operation_code);
        hardware_length = arp_protocol->arp_hardware_length;
        protocol_length = arp_protocol->arp_protocol_length;
        printf("ARP Hardware Type:%d\n", hardware_type);
        printf("ARP Potocol Type:%d\n", protocol_type);
        printf("ARP Hardware Lenght:%d\n", hardware_length);
        printf("ARP Potocol Lenght:%d\n", protocol_length);
        printf("ARP Operation:%d\n", operation_code);
        string protocol;
        switch (operation_code)
        {
        case 1:	printf("ARP Request Protocol\n");protocol="ARP Request Protocol!"; break;
        case 2:	printf("ARP Reply Protocol\n"); protocol="ARP Reply Protocol!";break;
        case 3:	printf("RARP Request Protocol\n"); protocol="RARP Request Protocol!";break;
        case 4:	printf("RARP Reply Protocol\n"); protocol="RARP Reply Protocol!";break;
        default:break;
        }

        printf("Ethernet Source Address is:\n");
        mac_string = arp_protocol->arp_source_ethernet_address;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
        memcpy((void*)&source_ip_address, (void*)&arp_protocol->arp_source_ip_address, sizeof(struct in_addr));
        printf("Source IP Address:%s\n", inet_ntoa(source_ip_address));
        printf("Ethernet Destination Address id:\n");
        mac_string = arp_protocol->arp_destination_ethernet_address;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
        memcpy((void*)&destination_ip_address, (void*)&arp_protocol->arp_destination_ip_address, sizeof(struct in_addr));
        printf("Destination IP Address:%s\n", inet_ntoa(destination_ip_address));

        string eth_source,eth_des,ip_source,ip_des;

        eth_source=get_address(eth_source,arp_protocol->arp_source_ethernet_address);
        eth_des=get_address(eth_des,arp_protocol->arp_destination_ethernet_address);
        ip_source=inet_ntoa(source_ip_address);
        ip_des=inet_ntoa(destination_ip_address);

        libpcap9::hardware_type.push_back(hardware_type);
        libpcap9::hardware_length.push_back(hardware_length);
        libpcap9::protocol_type.push_back(protocol_type);
        libpcap9::protocol_length.push_back(protocol_length);
        libpcap9::operation_code.push_back(operation_code);
        libpcap9::protocol.push_back(protocol);
        libpcap9::eth_source.push_back(eth_source);
        libpcap9::eth_des.push_back(eth_des);
        libpcap9::ip_source.push_back(ip_source);
        libpcap9::ip_des.push_back(ip_des);//arp

    }

    void libpcap9::ip_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
        struct ip_header* ip_protocol;
        u_int header_length;
        u_int offset;
        u_char tos;
        u_int16_t checksum;
        ip_protocol = (struct ip_header*)(packet_content + 14);

        checksum = ntohs(ip_protocol->ip_checksum);
        header_length = ip_protocol->ip_header_length * 4;
        tos = ip_protocol->ip_tos;
        offset = ntohs(ip_protocol->ip_off);

        printf("-------------- IP Protocol (Network Layer) -------------");
        printf("IP version: %d\n", ip_protocol->ip_version);
        printf("Header length: %d\n", header_length);
        printf("TOS: %d\n", tos);
        printf("Total length: %d\n", ntohs(ip_protocol->ip_length));
        printf("Identification: %d\n", ntohs(ip_protocol->ip_id));
        printf("Offset: %d\n", (offset & 0x1fff) * 8);
        printf("TTL: %d\n", ip_protocol->ip_ttl);
        printf("Protocol: %d\n", ip_protocol->ip_protocol);

        switch (ip_protocol->ip_protocol) {
        case 6:
            printf("The Transport Layer Protocol is TCP\n");
            break;
        case 17:
            printf("The Transport Layer Protocol is UDP\n");
            break;
        case 1:
            printf("The Transport Layer Protocol is ICMP\n");
            break;
        default:
            break;
        }

        printf("Header checksum: %d\n", checksum);
        printf("Source address: %s\n", inet_ntoa(ip_protocol->ip_source_address));
        printf("Destination address: %s\n", inet_ntoa(ip_protocol->ip_destination_address));

        switch (ip_protocol->ip_protocol) {
        case 6:
            tcp_protocol_packet_callback(argument,packet_header,packet_content);
            state=2;

            libpcap9::udp_source_port.push_back(0);
            libpcap9::udp_des_port.push_back(0);
            libpcap9::udp_service.push_back("0");
            libpcap9::udp_length.push_back(0);
            libpcap9::udp_checksum.push_back(0);//udp

            libpcap9::icmp_type.push_back(0);
            libpcap9::icmp_protocol.push_back("0");
            libpcap9::icmp_code.push_back(0);
            libpcap9::icmp_ids.push_back(0);
            libpcap9::icmp_seq_num.push_back(0);
            libpcap9::icmp_checksum.push_back(0);//icmp

            break;
        case 17:
            udp_protocol_packet_callback(argument,packet_header,packet_content);
            state=3;

            libpcap9::tcp_source_port.push_back(0);
            libpcap9::tcp_des_port.push_back(0);
            libpcap9::tcp_protocol.push_back("0");
            libpcap9::tcp_seq_num.push_back(0);
            libpcap9::tcp_ack_num.push_back(0);
            libpcap9::tcp_header_length.push_back(0);
            libpcap9::tcp_reserved.push_back(0);
            libpcap9::tcp_flags.push_back("0");
            libpcap9::tcp_win_size.push_back(0);
            libpcap9::tcp_checksum.push_back(0);
            libpcap9::tcp_u_pointer.push_back(0);//tcp

            libpcap9::icmp_type.push_back(0);
            libpcap9::icmp_protocol.push_back("0");
            libpcap9::icmp_code.push_back(0);
            libpcap9::icmp_ids.push_back(0);
            libpcap9::icmp_seq_num.push_back(0);
            libpcap9::icmp_checksum.push_back(0);//icmp



            break;
        case 1:
            icmp_protocol_packet_callback(argument,packet_header,packet_content);
            state=4;

            libpcap9::tcp_source_port.push_back(0);
            libpcap9::tcp_des_port.push_back(0);
            libpcap9::tcp_protocol.push_back("0");
            libpcap9::tcp_seq_num.push_back(0);
            libpcap9::tcp_ack_num.push_back(0);
            libpcap9::tcp_header_length.push_back(0);
            libpcap9::tcp_reserved.push_back(0);
            libpcap9::tcp_flags.push_back("0");
            libpcap9::tcp_win_size.push_back(0);
            libpcap9::tcp_checksum.push_back(0);
            libpcap9::tcp_u_pointer.push_back(0);//tcp

            libpcap9::udp_source_port.push_back(0);
            libpcap9::udp_des_port.push_back(0);
            libpcap9::udp_service.push_back("0");
            libpcap9::udp_length.push_back(0);
            libpcap9::udp_checksum.push_back(0);//udp

            break;
        default:
            break;
        }

        libpcap9::ip_version.push_back(ip_protocol->ip_version);
        libpcap9::ip_header_length.push_back(header_length);
        libpcap9::ip_tos.push_back(tos);
        libpcap9::ip_total_length.push_back(ntohs(ip_protocol->ip_length));
        libpcap9::ip_id.push_back(ntohs(ip_protocol->ip_id));
        libpcap9::ip_offset.push_back((offset & 0x1fff) * 8);
        libpcap9::ip_ttl.push_back(ip_protocol->ip_ttl);
        libpcap9::ip_protocol.push_back(ip_protocol->ip_protocol);
        libpcap9::ip_checksum.push_back(checksum);
        libpcap9::ip_source_address.push_back(inet_ntoa(ip_protocol->ip_source_address));
        libpcap9::ip_des_adddress.push_back(inet_ntoa(ip_protocol->ip_destination_address));



    }

    void libpcap9::ethernet_protocol_packet_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content) {
        u_short ethernet_type;
        struct ether_header* ethernet_protocol;
        u_char* mac_string;
        static int packet_number = 1;

        printf("************************************\n");
        printf("The %d IP packet is captured.\n", packet_number);

        printf("------------- Ethernet Protocol(Link Layer) ------------------\n");
        ethernet_protocol = (struct ether_header*)packet_content;

        printf("Ethernet type is: \n");
        ethernet_type = ntohs(ethernet_protocol->ether_type);

        printf("%04x\n", ethernet_type);
        switch (ethernet_type) {
        case 0x0800:
            printf("the network layer is IP protocol\n");
            break;
        case 0x0806:
            printf("the network layer is ARP protocol\n");
            break;
        case 0x8035:
            printf("the network layer is RARP protocol\n");
            break;
        default:
            break;
        }

        printf("mac source address is : \n");
        mac_string = ethernet_protocol->ether_shost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

        printf("mac destination address is: \n");
        mac_string = ethernet_protocol->ether_dhost;
        printf("%02x:%02x:%02x:%02x:%02x:%02x\n", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));

        switch (ethernet_type) {
        case 0x0806:
            arp_protocol_packet_callback(argument, packet_header, packet_content);

            libpcap9::ip_version.push_back(0);
            libpcap9::ip_header_length.push_back(0);
            libpcap9::ip_tos.push_back(0);
            libpcap9::ip_total_length.push_back(0);
            libpcap9::ip_id.push_back(0);
            libpcap9::ip_offset.push_back(0);
            libpcap9::ip_ttl.push_back(0);
            libpcap9::ip_protocol.push_back(0);
            libpcap9::ip_checksum.push_back(0);
            libpcap9::ip_source_address.push_back("0");
            libpcap9::ip_des_adddress.push_back("0");//ip

            libpcap9::tcp_source_port.push_back(0);
            libpcap9::tcp_des_port.push_back(0);
            libpcap9::tcp_protocol.push_back("0");
            libpcap9::tcp_seq_num.push_back(0);
            libpcap9::tcp_ack_num.push_back(0);
            libpcap9::tcp_header_length.push_back(0);
            libpcap9::tcp_reserved.push_back(0);
            libpcap9::tcp_flags.push_back("0");
            libpcap9::tcp_win_size.push_back(0);
            libpcap9::tcp_checksum.push_back(0);
            libpcap9::tcp_u_pointer.push_back(0);//tcp

            libpcap9::udp_source_port.push_back(0);
            libpcap9::udp_des_port.push_back(0);
            libpcap9::udp_service.push_back("0");
            libpcap9::udp_length.push_back(0);
            libpcap9::udp_checksum.push_back(0);//udp

            libpcap9::icmp_type.push_back(0);
            libpcap9::icmp_protocol.push_back("0");
            libpcap9::icmp_code.push_back(0);
            libpcap9::icmp_ids.push_back(0);
            libpcap9::icmp_seq_num.push_back(0);
            libpcap9::icmp_checksum.push_back(0);//icmp

            state=0;
        case 0x0800:
            ip_protocol_packet_callback(argument, packet_header, packet_content);

            libpcap9::hardware_type.push_back(0);
            libpcap9::hardware_length.push_back(0);
            libpcap9::protocol_type.push_back(0);
            libpcap9::protocol_length.push_back(0);
            libpcap9::operation_code.push_back(0);
            libpcap9::protocol.push_back("0");
            libpcap9::eth_source.push_back("0");
            libpcap9::eth_des.push_back("0");
            libpcap9::ip_source.push_back("0");
            libpcap9::ip_des.push_back("0");//arp

            state=1;
            break;
        default:
            break;
        }

        printf("***************************************\n");
        packet_number++;

//        adjust();

        string mac_source;
        string mac_des;

        for (int i=0;i<6;i++) {
            char temp[6];
            sprintf(temp, "%02x", ethernet_protocol->ether_shost[i]);
            string res=temp;
            mac_source=mac_source+res;
            if(i!=5){
                mac_source=mac_source+":";
            }
        }
        for (int i=0;i<6;i++) {
            char temp[6];
            sprintf(temp, "%02x", ethernet_protocol->ether_dhost[i]);
            string res=temp;
            mac_des=mac_des+res;
            if(i!=5){
                mac_des=mac_des+":";
            }
        }

        char type_id[100];
        sprintf(type_id,"%04x",ethernet_type);
        string temp=type_id;

        libpcap9::ethernet_type.push_back(temp);
        libpcap9::mac_source.push_back(mac_source);
        libpcap9::mac_des.push_back(mac_des);
    }

    void libpcap9::adjust(){
        switch (state) {
         case 0:
            libpcap9::ip_version.push_back(0);
            libpcap9::ip_header_length.push_back(0);
            libpcap9::ip_tos.push_back(0);
            libpcap9::ip_total_length.push_back(0);
            libpcap9::ip_id.push_back(0);
            libpcap9::ip_offset.push_back(0);
            libpcap9::ip_ttl.push_back(0);
            libpcap9::ip_protocol.push_back(0);
            libpcap9::ip_checksum.push_back(0);
            libpcap9::ip_source_address.push_back("0");
            libpcap9::ip_des_adddress.push_back("0");//ip

            libpcap9::tcp_source_port.push_back(0);
            libpcap9::tcp_des_port.push_back(0);
            libpcap9::tcp_protocol.push_back("0");
            libpcap9::tcp_seq_num.push_back(0);
            libpcap9::tcp_ack_num.push_back(0);
            libpcap9::tcp_header_length.push_back(0);
            libpcap9::tcp_reserved.push_back(0);
            libpcap9::tcp_flags.push_back("0");
            libpcap9::tcp_win_size.push_back(0);
            libpcap9::tcp_checksum.push_back(0);
            libpcap9::tcp_u_pointer.push_back(0);//tcp

            libpcap9::udp_source_port.push_back(0);
            libpcap9::udp_des_port.push_back(0);
            libpcap9::udp_service.push_back("0");
            libpcap9::udp_length.push_back(0);
            libpcap9::udp_checksum.push_back(0);//udp

            libpcap9::icmp_type.push_back(0);
            libpcap9::icmp_protocol.push_back("0");
            libpcap9::icmp_code.push_back(0);
            libpcap9::icmp_ids.push_back(0);
            libpcap9::icmp_seq_num.push_back(0);
            libpcap9::icmp_checksum.push_back(0);//icmp

            break;
        case 2:
            libpcap9::hardware_type.push_back(0);
            libpcap9::hardware_length.push_back(0);
            libpcap9::protocol_type.push_back(0);
            libpcap9::protocol_length.push_back(0);
            libpcap9::operation_code.push_back(0);
            libpcap9::protocol.push_back("0");
            libpcap9::eth_source.push_back("0");
            libpcap9::eth_des.push_back("0");
            libpcap9::ip_source.push_back("0");
            libpcap9::ip_des.push_back("0");//arp

            libpcap9::udp_source_port.push_back(0);
            libpcap9::udp_des_port.push_back(0);
            libpcap9::udp_service.push_back("0");
            libpcap9::udp_length.push_back(0);
            libpcap9::udp_checksum.push_back(0);//udp

            libpcap9::icmp_type.push_back(0);
            libpcap9::icmp_protocol.push_back("0");
            libpcap9::icmp_code.push_back(0);
            libpcap9::icmp_ids.push_back(0);
            libpcap9::icmp_seq_num.push_back(0);
            libpcap9::icmp_checksum.push_back(0);//icmp


            break;
        case 3:
            libpcap9::hardware_type.push_back(0);
            libpcap9::hardware_length.push_back(0);
            libpcap9::protocol_type.push_back(0);
            libpcap9::protocol_length.push_back(0);
            libpcap9::operation_code.push_back(0);
            libpcap9::protocol.push_back("0");
            libpcap9::eth_source.push_back("0");
            libpcap9::eth_des.push_back("0");
            libpcap9::ip_source.push_back("0");
            libpcap9::ip_des.push_back("0");//arp

            libpcap9::tcp_source_port.push_back(0);
            libpcap9::tcp_des_port.push_back(0);
            libpcap9::tcp_protocol.push_back("0");
            libpcap9::tcp_seq_num.push_back(0);
            libpcap9::tcp_ack_num.push_back(0);
            libpcap9::tcp_header_length.push_back(0);
            libpcap9::tcp_reserved.push_back(0);
            libpcap9::tcp_flags.push_back("0");
            libpcap9::tcp_win_size.push_back(0);
            libpcap9::tcp_checksum.push_back(0);
            libpcap9::tcp_u_pointer.push_back(0);//tcp

            libpcap9::icmp_type.push_back(0);
            libpcap9::icmp_protocol.push_back("0");
            libpcap9::icmp_code.push_back(0);
            libpcap9::icmp_ids.push_back(0);
            libpcap9::icmp_seq_num.push_back(0);
            libpcap9::icmp_checksum.push_back(0);//icmp
            break;
        case 4:
            libpcap9::hardware_type.push_back(0);
            libpcap9::hardware_length.push_back(0);
            libpcap9::protocol_type.push_back(0);
            libpcap9::protocol_length.push_back(0);
            libpcap9::operation_code.push_back(0);
            libpcap9::protocol.push_back("0");
            libpcap9::eth_source.push_back("0");
            libpcap9::eth_des.push_back("0");
            libpcap9::ip_source.push_back("0");
            libpcap9::ip_des.push_back("0");//arp

            libpcap9::tcp_source_port.push_back(0);
            libpcap9::tcp_des_port.push_back(0);
            libpcap9::tcp_protocol.push_back("0");
            libpcap9::tcp_seq_num.push_back(0);
            libpcap9::tcp_ack_num.push_back(0);
            libpcap9::tcp_header_length.push_back(0);
            libpcap9::tcp_reserved.push_back(0);
            libpcap9::tcp_flags.push_back("0");
            libpcap9::tcp_win_size.push_back(0);
            libpcap9::tcp_checksum.push_back(0);
            libpcap9::tcp_u_pointer.push_back(0);//tcp

            libpcap9::udp_source_port.push_back(0);
            libpcap9::udp_des_port.push_back(0);
            libpcap9::udp_service.push_back("0");
            libpcap9::udp_length.push_back(0);
            libpcap9::udp_checksum.push_back(0);//udp
            break;

        }
    }

    void libpcap9::solution()
    {
        char error_content[PCAP_ERRBUF_SIZE];
        pcap_t* pcap_handle;
        char* net_interface;
        struct bpf_program bpf_filter;
        char bpf_filter_string[] = "";
        bpf_u_int32 net_mask;
        bpf_u_int32 net_ip;
        net_interface = pcap_lookupdev(error_content);

        pcap_lookupnet(net_interface, &net_ip, &net_mask, error_content);

        pcap_handle = pcap_open_live(net_interface, BUFSIZ, 1, 0, error_content);

        pcap_compile(pcap_handle, &bpf_filter, bpf_filter_string, 0, net_ip);

        pcap_setfilter(pcap_handle, &bpf_filter);

        if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
            return;
        }

        pcap_loop(pcap_handle, libpcap9::number, ethernet_protocol_packet_callback, NULL);

        pcap_close(pcap_handle);
    }



