extern "C"
{
#include <inttypes.h>
#include <rte_cycles.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <stdint.h>
#include <unistd.h>
}
#include <cstdlib>
#include <map>
#include <string>
#include <thread>
#include <vector>
#include <list>

#define PORT_USED 0
#define BURST_SIZE 32

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32
#define MAX_QUEUE_NUM 64

#define UDP_SRC_PORT_PING 100
#define UDP_SRC_PORT_PONG 1000

struct __attribute__((packed)) ping_payload_h
{
    uint16_t task_ID;
    uint32_t task_start_tstamp;
    uint16_t circ_times;
    uint32_t next_hop_bit;
    uint8_t hop_times;
    uint32_t last_hop_delay;
    uint32_t last_hop_link;
};

struct __attribute__((packed)) pong_payload_h
{
    uint16_t task_ID;
    uint32_t task_start_tstamp;
    uint16_t path_count;
    uint32_t max_delay;
    uint32_t max_delay_link;
    uint32_t drop_link;
};

template <typename task_id_t = uint16_t, typename task_id_seq_t = uint32_t>
class task_manager
{
private:
    std::map<std::string, std::list<task_id_t>> available_task_ids;
    std::map<task_id_t, std::string> used_id_type;
    std::map<task_id_t, task_id_seq_t> task_id_seq_nums;

public:
    task_manager() {}

    void register_task_type(std::string type, task_id_t start, size_t max_jobs)
    {
        std::list<task_id_t> type_available_task_ids;
        for (task_id_t i = start; i < start + max_jobs; i++) {
            type_available_task_ids.push_back(i);
            task_id_seq_nums.emplace(i, 0);
        }
        available_task_ids.emplace(type, std::move(type_available_task_ids));
    }

    std::list<std::pair<task_id_t, task_id_seq_t>> schedule(std::string type, size_t max_size)
    {
        auto it = available_task_ids.find(type);
        if (it == available_task_ids.end())
            return std::list<std::pair<task_id_t, task_id_seq_t>>();
        auto type_available_task_ids = it->second;
        auto end = std::next(type_available_task_ids.begin(), std::min(type_available_task_ids.size(), max_size));
        std::list<std::pair<task_id_t, task_id_seq_t>> res;
        for (auto id_it = type_available_task_ids.begin(); id_it != end; id_it++) 
            res.push_back(std::make_pair(*id_it, ++task_id_seq_nums.at(*id_it))); 
        type_available_task_ids.erase(type_available_task_ids.begin(), end);
        return res;
    }

    void release_id(task_id_t task_id)
    {
        auto it = used_id_type.find(task_id);
        if (it == used_id_type.end())
            return;
        std::string type = it->second;
        available_task_ids.at(type).push_back(task_id);
    }
};

void build_pong_packet(struct rte_mbuf *mbuf, struct rte_ether_hdr *ping_hdr_eth, struct rte_ipv4_hdr *ping_hdr_ip, 
                       struct rte_udp_hdr *ping_hdr_udp, struct ping_payload_h *ping_payload) {

}

void build_ping_packet(struct rte_mbuf *mbuf, uint16_t task_ID, uint32_t task_seq_num, 
                       uint32_t sip, uint32_t dip, uint8_t hops) {

}

int dpdk_init(struct rte_mempool *mbuf_pool, int argc, char *argv[]);

int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    dpdk_init(mbuf_pool, argc, argv);

    task_manager<> manager;
    std::map<uint16_t, uint64_t> task_send_timestamp;
    std::vector<std::string> types{{"1"}, {"2"}, {"3"}};
    std::map<std::string, std::list<std::tuple<uint32_t, uint32_t, uint8_t>>> tasks;

    while (true)
    {
        // RECV
        struct rte_mbuf *recv_bufs[BURST_SIZE];
        struct rte_mbuf *send_bufs[BURST_SIZE];
        uint16_t send_size = 0;

        struct rte_ether_hdr *hdr_eth;
        struct rte_ipv4_hdr *hdr_ip;
        struct rte_udp_hdr *hdr_udp;

        uint16_t nb_rx;
        nb_rx = rte_eth_rx_burst(PORT_USED, 0, recv_bufs, BURST_SIZE); 

        for (uint16_t i = 0; i < nb_rx; i++)
        {
            struct rte_mbuf *mbuf = recv_bufs[i];
            hdr_eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            hdr_ip = (struct rte_ipv4_hdr *)(hdr_eth + 1);
            hdr_udp = (struct rte_udp_hdr *)(hdr_ip + 1);
            char *payload = (char *)(hdr_udp + 1);
            
            uint16_t src_port = rte_be_to_cpu_16(hdr_udp->src_port);
            switch (src_port) {
                case UDP_SRC_PORT_PING:
                    // GENERATE PONG PACKET
                    {
                        struct ping_payload_h *ping_payload = (struct ping_payload_h *)payload;
                        send_bufs[send_size] = rte_pktmbuf_alloc(mbuf_pool);

                        build_pong_packet(send_bufs[send_size], hdr_eth, hdr_ip, hdr_udp, ping_payload);

                        send_size += 1; 
                    }
                    break;
                case UDP_SRC_PORT_PONG: 
                    {
                        struct pong_payload_h *pong_payload = (struct pong_payload_h *)payload;
                        uint16_t task_ID = rte_be_to_cpu_16(pong_payload->task_ID);
                        uint64_t send_timestamp = task_send_timestamp[task_ID];
                        uint64_t recv_timestamp = rte_rdtsc();
                        printf("received pong packet of task %d, sent at  %lu, received at %lu, RTT %lu\n", 
                            task_ID, send_timestamp, recv_timestamp, recv_timestamp - send_timestamp);
                        manager.release_id(task_ID);
                    }
                    break;
            }

            rte_pktmbuf_free(mbuf);
        }

        // SEND
        std::list<uint32_t> send_ids;
        for (auto type : types) {
            std::list<std::tuple<uint32_t, uint32_t, uint8_t>> &type_tasks = tasks.at(type);
            std::list<std::pair<uint16_t, uint32_t>> available_ids = manager.schedule(type, type_tasks.size());
            for (auto [task_ID, task_seq_num] : available_ids) {
                send_ids.push_back(task_ID);
                auto [sip, dip, hops] = type_tasks.front();
                type_tasks.pop_front();

                send_bufs[send_size] = rte_pktmbuf_alloc(mbuf_pool);

                build_ping_packet(send_bufs[send_size], task_ID, task_seq_num, sip, dip, hops);

                send_size += 1;
            }
        }
        
        uint16_t nb_tx = rte_eth_tx_burst(PORT_USED, 0, send_bufs, send_size);
        uint64_t send_timestamp = rte_rdtsc();
        for (auto send_id : send_ids)
            task_send_timestamp.emplace(send_id, send_timestamp);
        if (unlikely(nb_tx < send_size)) {
            uint16_t buf;
            for (buf = nb_tx; buf < send_size; buf++) rte_pktmbuf_free(send_bufs[buf]);
            fprintf(stderr, "WARNING: failed to send %d pakcets", send_size - nb_tx);
        }
    }
}

int port_init(struct rte_mempool *mbuf_pool, uint16_t port)
{
    struct rte_eth_conf port_conf; // = port_conf_default;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port))
        return -1;

    const uint16_t rx_rings = 1, tx_rings = 1;
    memset(&port_conf, 0, sizeof(rte_eth_conf));
    rte_eth_dev_info_get(port, &dev_info);

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);

    if (retval != 0)
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);

    if (retval != 0)
        return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++)
    {
        retval = rte_eth_rx_queue_setup(
            port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0)
            return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++)
    {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd,
                                        rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0)
            return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           " %02" PRIx8 " %02" PRIx8 "\n",
           port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2],
           addr.addr_bytes[3], addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}

int dpdk_init(struct rte_mempool *mbuf_pool, int argc, char *argv[])
{
    unsigned nb_ports;
    uint16_t port = PORT_USED;
    uint16_t q;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    nb_ports = rte_eth_dev_count_avail();

    if (nb_ports < 1)
        rte_exit(EXIT_FAILURE, "Error: number of ports must be greater than one\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create(
        (std::string("MBUF_POOL") + std::to_string(q)).c_str(), NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %" PRIu16 "\n", q);

    /* Initialize all ports. */
    if (port_init(mbuf_pool, port) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port);

    return ret;
}
