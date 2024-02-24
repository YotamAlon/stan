#include <pcap.h>
#include <optional>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <linux/tcp.h>
#include "packet_reader.hpp"
using namespace std;


PacketReader::~PacketReader()
{
}

std::optional<Packet> PacketReader::read_packet() {
    while (int returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
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
            Packet packet;
            packet.len = header->len;

            struct iphdr* ip_header;
            ip_header = (struct iphdr*) (eth_header + 1);

            packet.sender = ip_header->saddr;
            packet.destination = ip_header->daddr;
            packet.protocol = ip_header->protocol;

            if (ip_header->protocol == IPPROTO_TCP) {
                struct tcphdr* tcp_header;
                tcp_header = (struct tcphdr*) (ip_header + 1);

                packet.syn = (bool)tcp_header->syn;
                packet.ack = (bool)tcp_header->ack;
                packet.seq = ntohl(tcp_header->seq);
            }
            return packet;
        }
    }
}