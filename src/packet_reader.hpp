#include <iostream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <linux/tcp.h>

struct Packet
{
    u_int len;
    uint32_t sender;
    uint32_t destination;
    uint8_t protocol;
    std::optional<bool> syn;
    std::optional<bool> ack;
    std::optional<u_int> seq;
};

class PacketReader
{
private:
    struct pcap_pkthdr *header;
    const u_char *data;
    char errbuff[PCAP_ERRBUF_SIZE];

public:
    pcap_t *pcap;
    PacketReader(const char* file)
    {
        std::cerr << "Reading packets from file " << file << std::endl;
        this->pcap = pcap_open_offline(file, this->errbuff);
        if (!this->pcap) {
            throw std::runtime_error("Stan: Unable to open pcap file");
        }
    }
    PacketReader(const char* dev, bool flag)
    {   
        std::cerr << "Reading packets from interface " << dev << std::endl;
        this->pcap = pcap_open_live(dev, BUFSIZ, true, 100, this->errbuff);
        if (!this->pcap) {
            throw std::runtime_error("Stan: Unable to open interface for reading");
        }
        std::cerr << "Interface " << dev << " opened for reading" << std::endl;
    }
    ~PacketReader();
    std::optional<Packet> read_packet();
};