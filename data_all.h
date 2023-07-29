#ifndef DATA_ALL_H
#define DATA_ALL_H

#include<vector>
#include<iostream>
#include<string>
#include<string.h>


#define STATE_RECEIVE "Receive"
#define STATE_SEND "Send"
#define PROTOCOL_IP "IP"
#define PROTOCOL_TCP "TCP"
#define PROTOCOL_UDP "UDP"
#define PROTOCOL_ARP "ARP"
#define PROTOCOL_ICMP "ICMP"

using namespace std;

class Data{
public:
    string state;
    string ip_src;
    string port_src;
    string ip_des;
    string port_des;
    string protocol;

    static vector<Data*> datas;

    Data(vector<string> &data){
        this->state=data.at(0);
        this->ip_src=data.at(1);
        this->port_src=data.at(2);
        this->ip_des=data.at(3);
        this->port_des=data.at(4);
        this->protocol=data.at(5);
    }

    string get_attr(int index){
        switch (index) {
            case 0:
                return this->state;
            case 1:
                return this->ip_src;
            case 2:
                return this->port_src;
            case 3:
                return this->ip_des;
            case 4:
                return this->port_des;
            case 5:
                return this->protocol;
        }

    }
};


#endif // DATA_ALL_H
