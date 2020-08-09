all: arp-spoof

arp-spoof: arp-spoof-main.cpp arphdr.cpp ethhdr.cpp ip.cpp mac.cpp get_mac_ip.cpp
	g++ -o $@ $^ -lpcap

clean:
	rm arp-spoof
