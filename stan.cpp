#include <string>
#include <iostream>
#include <pcap.h>
#include <unordered_map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <filesystem>
#include <linux/tcp.h>

using namespace std;

struct Stats {
    float kilobits;
    int packets;
    int connections;
};

int main(int argc, char *argv[]) {
    string file = argv[1];
    std::filesystem::path cwd = std::filesystem::current_path();
    std::unordered_map<uint32_t, Stats> stats_map;
 
    // Note: errbuf in pcap_open functions is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
    //       PCAP_ERRBUF_SIZE is defined as 256.
    // http://www.winpcap.org/docs/docs_40_2/html/group__wpcap__def.html
    char errbuff[PCAP_ERRBUF_SIZE];
 
    // Use pcap_open_offline
    // http://www.winpcap.org/docs/docs_41b5/html/group__wpcapfunc.html#g91078168a13de8848df2b7b83d1f5b69
    pcap_t* pcap = pcap_open_offline(file.c_str(), errbuff);
 
    // Create a header object:
    // http://www.winpcap.org/docs/docs_40_2/html/structpcap__pkthdr.html
    struct pcap_pkthdr *header;
 
    const u_char* data;
 
    u_int packetCount = 0;
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {

        string address;
 
        // Show the size in bytes of the packet
        float bits = header->len * 8;
 
        // Show a warning if the length captured is different
        if (header->len != header->caplen)
            printf("Warning! Capture size different than packet size: %ld bytes\n", header->len);
 
        // Show Epoch Time
        // printf("Epoch Time: %d:%d seconds\n", header->ts.tv_sec, header->ts.tv_usec);
        if (header->caplen < 8) {
            continue;
        }

        struct ether_header* eth_header;
        eth_header = (struct ether_header*) data;
        if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
            struct iphdr* ip_header;
            ip_header = (struct iphdr*) (data + sizeof(*eth_header));
            uint32_t sender = ip_header->saddr;
            uint32_t receiver = ip_header->daddr;
            stats_map[sender].kilobits += header->len;
            stats_map[sender].packets += 1;
            if (ip_header->protocol == IPPROTO_TCP) {
                struct tcphdr* tcp_header;
                tcp_header = (struct tcphdr*) (data + sizeof(*eth_header) + sizeof(*ip_header));
                if (tcp_header->syn && tcp_header->ack) {
                    stats_map[receiver].connections += 1;
                }
            }
        }
        // else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
        //     struct ip6_hdr *ip_header;
        //     ip_header = (struct ip6_hdr *) data[32];
        // }
    }

    std::cout << "IP \t bits \t packets \t conns" << std::endl;
    for (auto iter = stats_map.begin(); iter != stats_map.end(); ++iter) {
        auto cur = iter->first;
        struct in_addr addr = {cur};
        auto stats = stats_map[cur];
        std::cout << inet_ntoa(addr) << " \t" << stats.kilobits << " \t" << stats.packets << " \t" << stats.connections << std::endl;
    }
};


stringstream print_packet(pcap_pkthdr* header, const u_char* data)
{
    stringstream output;
    for (u_int i = 0; (i < header->caplen); i++)
    {
        // Start printing on the next after every 16 octets
        if ((i % 16) == 0)
            output << "\n";

        // Print each octet as hex (x), make sure there is always two characters (.2).
        output << "%.2x ", data[i];
    }
    return output;
}