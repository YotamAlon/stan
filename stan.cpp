#include <iostream>
#include <pcap.h>
#include <unordered_map>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <filesystem>
#include <linux/tcp.h>
#include <unordered_set>
#include "packet_reader.hpp"

using namespace std;

struct Stats
{
    float kilobits;
    int packets;
    int connections;
    unordered_set<int> syn_seqs;
};

int main(int argc, char *argv[])
{
    std::string file = argv[1];
    std::filesystem::path cwd = std::filesystem::current_path();
    std::unordered_map<uint32_t, Stats> stats_map;
    PacketReader *packet_reader = new PacketReader(file.c_str());

    while (std::optional<Packet> packet = packet_reader->read_packet())
    {
        uint32_t sender = packet->sender;
        stats_map[sender].kilobits += packet->len;
        stats_map[sender].packets += 1;
        if (packet->protocol == IPPROTO_TCP)
        {
            if (packet->syn && !packet->ack)
            {
                stats_map[sender].syn_seqs.insert(packet->seq.value());
            }
            else if (packet->ack && !packet->syn && stats_map[sender].syn_seqs.count(packet->seq.value() - 1))
            {
                stats_map[sender].connections += 1;
                stats_map[sender].syn_seqs.erase(packet->seq.value() - 1);
            }
        }
    }
    // else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    //     struct ip6_hdr *ip_header;
    //     ip_header = (struct ip6_hdr *) data[32];
    // }

    std::cout << "IP \t bits \t packets \t conns" << std::endl;
    for (auto iter = stats_map.begin(); iter != stats_map.end(); ++iter)
    {
        auto cur = iter->first;
        struct in_addr addr = {cur};
        auto stats = stats_map[cur];
        std::cout << inet_ntoa(addr) << " \t" << stats.kilobits << " \t" << stats.packets << " \t" << stats.connections << std::endl;
    }
};

stringstream print_packet(pcap_pkthdr *header, const u_char *data)
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