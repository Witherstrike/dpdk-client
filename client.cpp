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
#include <rte_launch.h>
#include <rte_spinlock.h>
}
#include <cstdlib>
#include <map>
#include <string>
#include <vector>
#include <list>

#include "task_loader.hpp"

#define PORT0 0
#define PORT1 1
static constexpr uint16_t kNumPorts = 2;

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
            return {};

        auto &lst = it->second;
        auto end = std::next(lst.begin(), std::min(lst.size(), max_size));

        std::list<std::pair<task_id_t, task_id_seq_t>> res;
        for (auto id_it = lst.begin(); id_it != end; ++id_it) {
            used_id_type[*id_it] = type;
            res.push_back({*id_it, ++task_id_seq_nums.at(*id_it)});
        }
        lst.erase(lst.begin(), end);
        return res;
    }

    void release_id(task_id_t task_id)
    {
        auto it = used_id_type.find(task_id);
        if (it == used_id_type.end())
            return;
        std::string type = it->second;
        used_id_type.erase(it);
        available_task_ids.at(type).push_back(task_id);
    }
};

void build_pong_packet(struct rte_mbuf *mbuf, struct rte_ether_hdr *ping_hdr_eth, struct rte_ipv4_hdr *ping_hdr_ip, 
                       struct rte_udp_hdr *ping_hdr_udp, struct ping_payload_h *ping_payload) {
    struct rte_ether_hdr *hdr_eth;
    struct rte_ipv4_hdr *hdr_ip;
    struct rte_udp_hdr *hdr_udp;
    struct pong_payload_h *payload;

    payload = (struct pong_payload_h *)rte_pktmbuf_append(mbuf, sizeof(struct pong_payload_h));
    memset(payload, 0, sizeof(struct pong_payload_h));
    payload->task_ID = ping_payload->task_ID;
    payload->task_start_tstamp = ping_payload->task_start_tstamp;

    hdr_udp = (struct rte_udp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_udp_hdr));
    memset(hdr_udp, 0, sizeof(struct rte_udp_hdr));
    hdr_udp->src_port = htons(1000);
    hdr_udp->dst_port = htons(100); 
    hdr_udp->dgram_len = htons(sizeof(struct pong_payload_h) + sizeof(struct rte_udp_hdr));
    hdr_udp->dgram_cksum = 0;

    hdr_ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
    memset(hdr_ip, 0, sizeof(struct rte_ipv4_hdr));
    hdr_ip->version_ihl = 0x45;
    hdr_ip->total_length =
        htons(sizeof(struct pong_payload_h) + sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr));
    hdr_ip->time_to_live = 64;
    hdr_ip->next_proto_id = 100;
    hdr_ip->src_addr = ping_hdr_ip->dst_addr;
    hdr_ip->dst_addr = ping_hdr_ip->src_addr;

    hdr_eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
    memset(hdr_eth, 0, sizeof(struct rte_ether_hdr));
    hdr_eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    hdr_udp->dgram_cksum = rte_ipv4_udptcp_cksum(hdr_ip, hdr_udp);
    hdr_ip->hdr_checksum = rte_ipv4_cksum(hdr_ip);
}

void build_ping_packet(struct rte_mbuf *mbuf, uint16_t task_ID, uint32_t task_seq_num, 
                       uint32_t sip, uint32_t dip, uint8_t hops) {  
    struct rte_ether_hdr *hdr_eth;
    struct rte_ipv4_hdr *hdr_ip;
    struct rte_udp_hdr *hdr_udp;
    struct ping_payload_h *payload;

    payload = (struct ping_payload_h *)rte_pktmbuf_append(mbuf, sizeof(struct ping_payload_h));
    memset(payload, 0, sizeof(struct ping_payload_h));
    payload->task_ID = htons(task_ID);
    payload->task_start_tstamp = htonl(task_seq_num);
    payload->hop_times = hops;

    hdr_udp = (struct rte_udp_hdr *) rte_pktmbuf_prepend(mbuf, sizeof(struct rte_udp_hdr));
    memset(hdr_udp, 0, sizeof(struct rte_udp_hdr));
    hdr_udp->src_port = htons(100);
    hdr_udp->dst_port = htons(1000); 
    hdr_udp->dgram_len = htons(sizeof(struct ping_payload_h) + sizeof(struct rte_udp_hdr));
    hdr_udp->dgram_cksum = 0;

    hdr_ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
    memset(hdr_ip, 0, sizeof(struct rte_ipv4_hdr));
    hdr_ip->version_ihl = 0x45;
    hdr_ip->total_length =
        htons(sizeof(struct ping_payload_h) + sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr));
    hdr_ip->time_to_live = 64;
    hdr_ip->next_proto_id = 16;
    hdr_ip->src_addr = htonl(sip);
    hdr_ip->dst_addr = htonl(dip);

    hdr_eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
    memset(hdr_eth, 0, sizeof(struct rte_ether_hdr));
    hdr_eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);
    hdr_eth->src_addr =  (struct rte_ether_addr){ .addr_bytes = {0x04,0x42,0x1a,0x08,0x87,0xf0} };

    hdr_udp->dgram_cksum = rte_ipv4_udptcp_cksum(hdr_ip, hdr_udp);
    hdr_ip->hdr_checksum = rte_ipv4_cksum(hdr_ip);
}

int dpdk_init(struct rte_mempool *&mbuf_pool, int argc, char *argv[]);

struct shared_state {
    task_manager<> *manager;
    std::map<uint16_t, uint64_t> *task_send_timestamp;
    rte_spinlock_t lock;
};

struct port_ctx {
    uint16_t port_id;
    uint16_t queue_id;
    rte_mempool *mbuf_pool;

    shared_state *shared;

    // 每口独立任务队列
    std::map<std::string, std::list<std::tuple<uint32_t, uint32_t, uint8_t>>> tasks;
};

static int port_worker(void *arg)
{
    auto *ctx = static_cast<port_ctx*>(arg);

    while (true) {
        struct rte_mbuf *recv_bufs[BURST_SIZE];
        struct rte_mbuf *send_bufs[BURST_SIZE];
        uint16_t send_size = 0;

        uint16_t nb_rx = rte_eth_rx_burst(ctx->port_id, ctx->queue_id, recv_bufs, BURST_SIZE);
        for (uint16_t i = 0; i < nb_rx; i++) {
            struct rte_mbuf *mbuf = recv_bufs[i];

            auto *hdr_eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);
            auto *hdr_ip  = (struct rte_ipv4_hdr *)(hdr_eth + 1);
            auto *hdr_udp = (struct rte_udp_hdr *)(hdr_ip + 1);
            char *payload = (char *)(hdr_udp + 1);

            uint16_t src_port = rte_be_to_cpu_16(hdr_udp->src_port);
            if (src_port == UDP_SRC_PORT_PING) {
                auto *ping_payload = (struct ping_payload_h *)payload;
                uint16_t task_ID = rte_be_to_cpu_16(ping_payload->task_ID);
                printf("[port %u] recv ping task %u -> schedule pong\n", ctx->port_id, task_ID);

                send_bufs[send_size] = rte_pktmbuf_alloc(ctx->mbuf_pool);
                build_pong_packet(send_bufs[send_size], hdr_eth, hdr_ip, hdr_udp, ping_payload);
                send_size++;
            } else if (src_port == UDP_SRC_PORT_PONG) {
                auto *pong_payload = (struct pong_payload_h *)payload;
                uint16_t task_ID = rte_be_to_cpu_16(pong_payload->task_ID);

                uint64_t recv_timestamp = rte_rdtsc();
                uint64_t send_timestamp = 0;

                rte_spinlock_lock(&ctx->shared->lock);
                auto &ts = *ctx->shared->task_send_timestamp;
                auto it = ts.find(task_ID);
                if (it != ts.end()) send_timestamp = it->second;
                ctx->shared->manager->release_id(task_ID);
                rte_spinlock_unlock(&ctx->shared->lock);

                printf("[port %u] recv pong task %u, sent %lu recv %lu rtt %lu\n",
                       ctx->port_id, task_ID, send_timestamp, recv_timestamp,
                       (send_timestamp ? (recv_timestamp - send_timestamp) : 0UL));
            }

            rte_pktmbuf_free(mbuf);
        }

        std::list<uint16_t> send_ids;

        for (auto &[type, type_tasks] : ctx->tasks) {
            if (type_tasks.empty()) continue;

            rte_spinlock_lock(&ctx->shared->lock);
            auto ids = ctx->shared->manager->schedule(type, type_tasks.size());
            rte_spinlock_unlock(&ctx->shared->lock);

            for (auto [task_ID, task_seq_num] : ids) {
                if (type_tasks.empty() || send_size == BURST_SIZE) break;

                auto [sip, dip, hops] = type_tasks.front();
                type_tasks.pop_front();

                send_bufs[send_size] = rte_pktmbuf_alloc(ctx->mbuf_pool);
                build_ping_packet(send_bufs[send_size], task_ID, task_seq_num, sip, dip, hops);

                printf("[port %u] schedule ping id %u seq %u sip %u dip %u hops %u\n",
                       ctx->port_id, task_ID, task_seq_num, sip, dip, hops);

                send_ids.push_back(task_ID);
                send_size++;
            }
            if (send_size == BURST_SIZE) break;
        }

        if (send_size) {
            uint16_t nb_tx = rte_eth_tx_burst(ctx->port_id, ctx->queue_id, send_bufs, send_size);
            uint64_t send_timestamp = rte_rdtsc();

            rte_spinlock_lock(&ctx->shared->lock);
            for (auto id : send_ids)
                (*ctx->shared->task_send_timestamp)[id] = send_timestamp;
            rte_spinlock_unlock(&ctx->shared->lock);

            if (unlikely(nb_tx < send_size)) {
                for (uint16_t b = nb_tx; b < send_size; b++)
                    rte_pktmbuf_free(send_bufs[b]);
                fprintf(stderr, "[port %u] WARNING: failed to send %u packets\n",
                        ctx->port_id, (unsigned)(send_size - nb_tx));
            }
        }
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct rte_mempool *mbuf_pool;
    int ret = dpdk_init(mbuf_pool, argc, argv);

    argc -= ret;
    argv += ret;

    // 两个端口各自的 task 文件
    std::string tasks_path0("tasks/0.task");
    std::string tasks_path1("tasks/1.task");
    std::string config_path("tasks/1.config");

    if (argc > 1) tasks_path0 = argv[1];
    if (argc > 2) tasks_path1 = argv[2];
    if (argc > 3) config_path = argv[3];

    task_manager<> manager;
    std::map<uint16_t, uint64_t> task_send_timestamp;

    auto tasks0 = load_tasks(tasks_path0);
    auto tasks1 = load_tasks(tasks_path1);

    auto type_config = load_config(config_path);
    for (auto [type, start, max_jobs] : type_config)
        manager.register_task_type(type, start, max_jobs);

    shared_state shared{&manager, &task_send_timestamp};
    rte_spinlock_init(&shared.lock);

    static port_ctx ctx0, ctx1;
    ctx0 = {PORT0, 0, mbuf_pool, &shared, std::move(tasks0)};
    ctx1 = {PORT1, 0, mbuf_pool, &shared, std::move(tasks1)};

    unsigned main_lcore = rte_lcore_id();
    unsigned lcore0 = rte_get_next_lcore(main_lcore, 1, 0);
    unsigned lcore1 = rte_get_next_lcore(lcore0, 1, 0);
    if (lcore0 == RTE_MAX_LCORE || lcore1 == RTE_MAX_LCORE)
        rte_exit(EXIT_FAILURE, "Need at least 2 worker lcores\n");

    rte_eal_remote_launch(port_worker, &ctx0, lcore0);
    rte_eal_remote_launch(port_worker, &ctx1, lcore1);

    rte_eal_mp_wait_lcore();
    return 0;
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

int dpdk_init(struct rte_mempool *&mbuf_pool, int argc, char *argv[])
{
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    unsigned nb_ports = rte_eth_dev_count_avail();
    if (nb_ports < 2)
        rte_exit(EXIT_FAILURE, "Error: need at least 2 ports, got %u\n", nb_ports);

    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL", NUM_MBUFS * 2, // 两口
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL)
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    if (port_init(mbuf_pool, PORT0) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", PORT0);
    if (port_init(mbuf_pool, PORT1) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %u\n", PORT1);

    return ret;
}