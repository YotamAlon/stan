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
    PacketReader(const char *file)
    {
        // Note: errbuf in pcap_open functions is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
        //       PCAP_ERRBUF_SIZE is defined as 256.
        // http://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html
        char errbuff[PCAP_ERRBUF_SIZE];

        // Use pcap_open_offline
        // http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
        pcap_t *pcap = pcap_open_offline(file, errbuff);

        // Create a header object:
        // http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
        struct pcap_pkthdr *header;

        const u_char *data;
    }
    ~PacketReader();
    std::optional<Packet> read_packet();
};