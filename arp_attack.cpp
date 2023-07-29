#include"arp_attack.h"
#include"core.h"

//char* ARP_attack::network_interface;
//char* ARP_attack::local_ip;
//char* ARP_attack::local_mac;

vector<string> ARP_attack::network_interface_all;
vector<string> ARP_attack::local_ip_all;
vector<string> ARP_attack::local_mac_all;

vector<string> ARP_attack::contents;
vector<string> ARP_attack::ips;
vector<string> ARP_attack::hw_type;
vector<string> ARP_attack::flags;
vector<string> ARP_attack::hw_address;
vector<string> ARP_attack::masks;
vector<string> ARP_attack::devices;

uint8_t ARP_attack::infinite_loop;
string ARP_attack::log;
int ARP_attack::attack_times;
string ARP_attack::arp_dump;

void ARP_attack::get_arp_dump(unsigned char *buff,int len){
    char* string=(char*)malloc(1024*sizeof (char));
    memset(string,0,1024);

    int i,j;
    printf(" Frame Dump:\n");
    Core::res+=" Frame Dump:\n";
    for(i=0;i<len;i+=16){
        //16
        for(j=i;j<i+16&&j<len;j++){
            printf("%02x",buff[j]);
            sprintf(string,"%02x",buff[j]);
            ARP_attack::arp_dump+=string;
            memset(string,0,1024);
            if(j%2==1){
                printf(" ");
                ARP_attack::arp_dump+=" ";
            }

        }
        if(j==len&&len%16!=0)
            for(j=0;j<40-(len%16)*2.5;j++){
                printf(" ");
                ARP_attack::arp_dump+=" ";
            }
        printf("    ");
        ARP_attack::arp_dump+="    ";
        //ASCII
        for(j=i;j<i+16&&j<len;j++){
            if((buff[j]>=0x20)&&(buff[j]<=0x7e)){
                putchar(buff[j]);
                sprintf(string,"%c",buff[j]);
                ARP_attack::arp_dump+=string;
                memset(string,0,1024);
            }else{
                printf(".");
                ARP_attack::arp_dump+=".";
            }

        }
        printf("\n");
        ARP_attack::arp_dump+="\n";
        fflush(stdout);
    }
}

void ARP_attack::init(){
    ARP_attack::network_interface_all.clear();
    ARP_attack::local_ip_all.clear();
    ARP_attack::local_mac_all.clear();

    ARP_attack::contents.clear();
    ARP_attack::ips.clear();
    ARP_attack::hw_type.clear();
    ARP_attack::flags.clear();
    ARP_attack::hw_address.clear();
    ARP_attack::masks.clear();
    ARP_attack::devices.clear();

    ARP_attack::infinite_loop=1;
    ARP_attack::log="";
    ARP_attack::attack_times=0;
    ARP_attack::arp_dump="";

}//conflict??

int ARP_attack::get_default_config(){
    int fd;
    int interfaceNum = 0;
    struct ifreq buf[16];
    struct ifconf ifc;
    struct ifreq ifrcopy;
    char mac[18] = {0};
    char ip[32] = {0};
    char broadAddr[32] = {0};
    char subnetMask[32] = {0};

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("socket");

        close(fd);
        return -1;
    }

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = (caddr_t)buf;
    if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
    {
        interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
        printf("interface num = %d\n", interfaceNum);
        while (interfaceNum-- > 0)
        {
            printf("\ndevice name: %s\n", buf[interfaceNum].ifr_name);

            string network_interface;//
            network_interface=buf[interfaceNum].ifr_name;
            ARP_attack::network_interface_all.push_back(network_interface);//add device

            //ignore the interface that not up or not runing
            ifrcopy = buf[interfaceNum];
            if (ioctl(fd, SIOCGIFFLAGS, &ifrcopy))
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);

                close(fd);
                return -1;
            }

            //get the mac of this interface
            if (!ioctl(fd, SIOCGIFHWADDR, (char *)(&buf[interfaceNum])))
            {
                memset(mac, 0, sizeof(mac));
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],

                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
                    (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);

                string mac_address=mac;
                ARP_attack::local_mac_all.push_back(mac_address);//add mac

                printf("device mac: %s\n", mac);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
                return -1;
            }

            //get the IP of this interface

            if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[interfaceNum]))
            {
                snprintf(ip, sizeof(ip), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_addr))->sin_addr));
                printf("device ip: %s\n", ip);

                string ip_address=ip;
                ARP_attack::local_ip_all.push_back(ip_address);//add ip

            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
                return -1;
            }

            //get the broad address of this interface

            if (!ioctl(fd, SIOCGIFBRDADDR, &buf[interfaceNum]))
            {
                snprintf(broadAddr, sizeof(broadAddr), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_broadaddr))->sin_addr));
                printf("device broadAddr: %s\n", broadAddr);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
                return -1;
            }

            //get the subnet mask of this interface
            if (!ioctl(fd, SIOCGIFNETMASK, &buf[interfaceNum]))
            {
                snprintf(subnetMask, sizeof(subnetMask), "%s",
                    (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_netmask))->sin_addr));
                printf("device subnetMask: %s\n", subnetMask);
            }
            else
            {
                printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
                close(fd);
                return -1;

            }
        }
    }
    else
    {
        printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}

void ARP_attack::get_arp_table(){
    //cout<<"before"<<endl;
    system("cat /proc/net/arp > arp_table.txt");
    //cout<<"after"<<endl;


    char buf[MAX_LINE];  /*缓冲区*/
    FILE *fp;            /*文件指针*/
    if((fp = fopen("arp_table.txt","r")) == NULL){
        perror("fail to read");
        exit (1) ;
    }
    while (fscanf(fp, "%s", buf) != EOF){
        //printf("%s\n", buf);
        string content=buf;
        ARP_attack::contents.push_back(content);
    }
    for(int index=0;index<ARP_attack::contents.size()-9;index=index+6){
        ARP_attack::ips.push_back(ARP_attack::contents.at(index+9));
        ARP_attack::hw_type.push_back(ARP_attack::contents.at(index+10));
        ARP_attack::flags.push_back(ARP_attack::contents.at(index+11));
        ARP_attack::hw_address.push_back(ARP_attack::contents.at(index+12));
        ARP_attack::masks.push_back(ARP_attack::contents.at(index+13));
        ARP_attack::devices.push_back(ARP_attack::contents.at(index+14));
    }
}



//class ARP_cpp{
//public:
//    int ARP_attack::get_default_config(){
//        int fd;
//        int interfaceNum = 0;
//        struct ifreq buf[16];
//        struct ifconf ifc;
//        struct ifreq ifrcopy;
//        char mac[18] = {0};
//        char ip[32] = {0};
//        char broadAddr[32] = {0};
//        char subnetMask[32] = {0};

//        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
//        {
//            perror("socket");

//            close(fd);
//            return -1;
//        }

//        ifc.ifc_len = sizeof(buf);
//        ifc.ifc_buf = (caddr_t)buf;
//        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))
//        {
//            interfaceNum = ifc.ifc_len / sizeof(struct ifreq);
//            printf("interface num = %d\n", interfaceNum);
//            while (interfaceNum-- > 0)
//            {
//                printf("\ndevice name: %s\n", buf[interfaceNum].ifr_name);

//                string network_interface;//
//                network_interface=buf[interfaceNum].ifr_name;
//                ARP_attack::network_interface_all.push_back(network_interface);//add device

//                //ignore the interface that not up or not runing
//                ifrcopy = buf[interfaceNum];
//                if (ioctl(fd, SIOCGIFFLAGS, &ifrcopy))
//                {
//                    printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);

//                    close(fd);
//                    return -1;
//                }

//                //get the mac of this interface
//                if (!ioctl(fd, SIOCGIFHWADDR, (char *)(&buf[interfaceNum])))
//                {
//                    memset(mac, 0, sizeof(mac));
//                    snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
//                        (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[0],
//                        (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[1],
//                        (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[2],

//                        (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[3],
//                        (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[4],
//                        (unsigned char)buf[interfaceNum].ifr_hwaddr.sa_data[5]);

//                    string mac_address=mac;
//                    ARP_attack::local_mac_all.push_back(mac_address);//add mac

//                    printf("device mac: %s\n", mac);
//                }
//                else
//                {
//                    printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
//                    close(fd);
//                    return -1;
//                }

//                //get the IP of this interface

//                if (!ioctl(fd, SIOCGIFADDR, (char *)&buf[interfaceNum]))
//                {
//                    snprintf(ip, sizeof(ip), "%s",
//                        (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_addr))->sin_addr));
//                    printf("device ip: %s\n", ip);

//                    string ip_address=ip;
//                    ARP_attack::local_ip_all.push_back(ip_address);//add ip

//                }
//                else
//                {
//                    printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
//                    close(fd);
//                    return -1;
//                }

//                //get the broad address of this interface

//                if (!ioctl(fd, SIOCGIFBRDADDR, &buf[interfaceNum]))
//                {
//                    snprintf(broadAddr, sizeof(broadAddr), "%s",
//                        (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_broadaddr))->sin_addr));
//                    printf("device broadAddr: %s\n", broadAddr);
//                }
//                else
//                {
//                    printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
//                    close(fd);
//                    return -1;
//                }

//                //get the subnet mask of this interface
//                if (!ioctl(fd, SIOCGIFNETMASK, &buf[interfaceNum]))
//                {
//                    snprintf(subnetMask, sizeof(subnetMask), "%s",
//                        (char *)inet_ntoa(((struct sockaddr_in *)&(buf[interfaceNum].ifr_netmask))->sin_addr));
//                    printf("device subnetMask: %s\n", subnetMask);
//                }
//                else
//                {
//                    printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
//                    close(fd);
//                    return -1;

//                }
//            }
//        }
//        else
//        {
//            printf("ioctl: %s [%s:%d]\n", strerror(errno), __FILE__, __LINE__);
//            close(fd);
//            return -1;
//        }

//        close(fd);

//        return 0;
//    }

//    void get_arp_table(){
//        //cout<<"before"<<endl;
//        system("cat /proc/net/arp > arp_table.txt");
//        //cout<<"after"<<endl;


//        char buf[MAX_LINE];  /*缓冲区*/
//        FILE *fp;            /*文件指针*/
//        if((fp = fopen("arp_table.txt","r")) == NULL){
//            perror("fail to read");
//            exit (1) ;
//        }
//        while (fscanf(fp, "%s", buf) != EOF){
//            //printf("%s\n", buf);
//            string content=buf;
//            ARP_attack::contents.push_back(content);
//        }
//        for(int index=0;index<ARP_attack::contents.size()-9;index=index+6){
//            ARP_attack::ips.push_back(ARP_attack::contents.at(index+9));
//            ARP_attack::hw_type.push_back(ARP_attack::contents.at(index+10));
//            ARP_attack::flags.push_back(ARP_attack::contents.at(index+11));
//            ARP_attack::hw_address.push_back(ARP_attack::contents.at(index+12));
//            ARP_attack::masks.push_back(ARP_attack::contents.at(index+13));
//            ARP_attack::devices.push_back(ARP_attack::contents.at(index+14));
//        }
//    }
//};


