#include <string>
#include <stdexcept>

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
    pcap_t *pcap;
    struct pcap_pkthdr *header;
    const u_char *data;
    char errbuff[PCAP_ERRBUF_SIZE];

public:
    PacketReader(std::string file)
    {
        this->pcap = pcap_open_offline(file.c_str(), this->errbuff);
        if (!this->pcap) {
            throw std::runtime_error("Unable to open pcap file");
        }
    }
    ~PacketReader();
    std::optional<Packet> read_packet();
};