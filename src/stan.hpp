#include <iostream>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include "packet_reader.hpp"
#include <atomic>
#include <csignal>
#include <thread>
#include <chrono>

std::atomic<bool> stop = false;

struct Stats
{
    float kilobits;
    int packets;
    int connections;
    std::unordered_set<int> syn_seqs;
};

enum Mode
{
    Live,
    Read,
};

void handle_signal(int sig)
{
    if (!stop)
    {
        std::cerr << " - CTRL+C caught. Printing stats and exiting ..." << std::endl;
        stop = true;
    }
}

std::stringstream print_packet(const pcap_pkthdr *header, const u_char *data)
{
    std::stringstream output;
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

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    std::cout << print_packet(pkthdr, packet).str() << std::endl;
}

class Stan
{
private:
    std::unordered_map<uint32_t, Stats> stats_map;
    PacketReader *packet_reader;
    int count;
    void print_stats(std::unordered_map<uint32_t, Stats> &stats_map)
    {
        std::cout << "IP \t bits \t packets \t conns" << std::endl;
        for (auto iter = stats_map.begin(); iter != stats_map.end(); ++iter)
        {
            auto cur = iter->first;
            struct in_addr addr = {cur};
            auto stats = stats_map[cur];
            std::cout << inet_ntoa(addr) << " \t" << stats.kilobits << " \t" << stats.packets << " \t" << stats.connections << std::endl;
        }
    };
    void handle_packet(Packet *packet)
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
        count++;
        if (count % 10 == 0)
        {
            std::cerr << "Read " << count << " packets" << std::endl;
        }
    };

public:
    Stan(Mode mode, std::string source)
    {
        std::signal(SIGINT, handle_signal);

        if (mode == Read)
        {
            packet_reader = new PacketReader(source.c_str());
        }
        else
        {
            packet_reader = new PacketReader(source.c_str(), true);
        }
    }
    ~Stan() {}

    void run()
    {
        bool first_loop = true;

        while (!stop)
        {
            std::optional<Packet> packet = packet_reader->read_packet();
            if (packet)
            {
                handle_packet(&packet.value());
            }
        }
        print_stats(stats_map);
    }
};