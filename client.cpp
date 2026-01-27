#include "pkt_processor.h"
#include "agent_client.h"
#include "solver.h"
#include "utils.h"

#include <cstdio>
#include <cstdint>
#include <cinttypes>
#include <unistd.h>
#include <time.h>

#include <bits/getopt_core.h>
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>

#include <set>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

#define LPM_TXT_FILEPATH \
    "/home/lab1806/yinqh/bplus-tree-p4-offloading/switch/lpm_offloading_cmds.txt"

#define LPM_CACHE_CAPACITY 73000

// #define BTREE_DEBUG

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

// #define LOCAL_TEST

/* static const struct rte_eth_conf port_conf_default = {
    .rxmode =
        {
            .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};
 */
/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf; // = port_conf_default;
    memset(&port_conf, 0, sizeof(port_conf));

    const uint16_t rx_rings = 1, tx_rings = 1;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_txconf txconf;

    if (!rte_eth_dev_is_valid_port(port)) return -1;

    retval = rte_eth_dev_info_get(port, &dev_info);
    if (retval != 0) {
        printf("Error during getting device (port %u) info: %s\n", port, strerror(-retval));
        return retval;
    }

    if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
        port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    /* Configure the Ethernet device. */
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0) return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0) return retval;

    /* Allocate and set up 1 RX queue per Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval =
            rte_eth_rx_queue_setup(port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
        if (retval < 0) return retval;
    }

    txconf = dev_info.default_txconf;
    txconf.offloads = port_conf.txmode.offloads;
    /* Allocate and set up 1 TX queue per Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(port, q, nb_txd, rte_eth_dev_socket_id(port), &txconf);
        if (retval < 0) return retval;
    }

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0) return retval;

    /* Display the port MAC address. */
    struct rte_ether_addr addr;
    retval = rte_eth_macaddr_get(port, &addr);
    if (retval != 0) return retval;

    printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 " %02" PRIx8
           "\n",
           port, addr.addr_bytes[0], addr.addr_bytes[1], addr.addr_bytes[2], addr.addr_bytes[3],
           addr.addr_bytes[4], addr.addr_bytes[5]);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    retval = rte_eth_promiscuous_enable(port);
    if (retval != 0) return retval;

    return 0;
}

void process_packet(bmap &bt, AgentClient *agent, struct rte_mbuf *buf) {
    uint8_t *ptr = rte_pktmbuf_mtod(buf, uint8_t *);

    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_udp_hdr *udp_hdr;
    struct KVPHeader *kvp_hdr;

    /* Parsing Ethernet */
    eth_hdr = (struct rte_ether_hdr *)ptr;
    uint16_t ether_type = rte_be_to_cpu_16(eth_hdr->ether_type);
    switch (ether_type) {
        case RTE_ETHER_TYPE_IPV4:
            ptr += sizeof(struct rte_ether_hdr);
            break;
        default:
            printf("Not IPv4. Ignoring.\n");
            return;
    }

    /* Parsing IPv4 */
    ipv4_hdr = (struct rte_ipv4_hdr *)ptr;
    uint8_t next_proto_id = ipv4_hdr->next_proto_id;
    switch (next_proto_id) {
        case IPPROTO_UDP:
            ptr += (ipv4_hdr->version_ihl & RTE_IPV4_HDR_IHL_MASK) * RTE_IPV4_IHL_MULTIPLIER;
            break;
        default:
            printf("Not UDP. Ignoring.\n");
            return;
    }

    /* Parsing UDP */
    udp_hdr = (struct rte_udp_hdr *)ptr;
    uint16_t dport = rte_be_to_cpu_16(udp_hdr->dst_port);
    ptr += sizeof(struct rte_udp_hdr);
    /* switch (dport) {
        case KVP_PORT:
            ptr += sizeof(struct rte_udp_hdr);
            break;
        default:
            printf("Not expected UDP port %u. Ignoring.\n", dport);
            return;
    } */

    /* Parsing KVP */
    kvp_hdr = (KVPHeader *)ptr;
    bool ok = process_kvp(bt, agent, kvp_hdr);
    if (!ok) printf("process_kvp failed\n");

    /* Construct reply packet */
    rte_be16_t temp16 = udp_hdr->dst_port;
    udp_hdr->dst_port = udp_hdr->src_port;
    udp_hdr->src_port = temp16;

    rte_be32_t temp32 = ipv4_hdr->dst_addr;
    ipv4_hdr->dst_addr = ipv4_hdr->src_addr;
    ipv4_hdr->src_addr = temp32;

    rte_ether_addr temp_mac = eth_hdr->dst_addr;
    eth_hdr->dst_addr = eth_hdr->src_addr;
    eth_hdr->src_addr = temp_mac;
}

static __rte_noreturn void lcore_main(bmap &bt, AgentClient *agent) {
    uint16_t port;
    RTE_ETH_FOREACH_DEV(port)
    if (rte_eth_dev_socket_id(port) >= 0 && rte_eth_dev_socket_id(port) != (int)rte_socket_id())
        printf(
            "WARNING, port %u is on remote NUMA node to "
            "polling thread.\n\tPerformance will "
            "not be optimal.\n",
            port);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n", rte_lcore_id());

    for (;;) {
        RTE_ETH_FOREACH_DEV(port) {
            struct rte_mbuf *bufs[BURST_SIZE];
            const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

            if (unlikely(nb_rx == 0)) continue;

            /* Process packets one by one */
            for (int i = 0; i < nb_rx; i++) {
                process_packet(bt, agent, bufs[i]);
            }

            const uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);

            /* Free any unsent packets. */
            if (unlikely(nb_tx < nb_rx)) {
                uint16_t buf;
                for (buf = nb_tx; buf < nb_rx; buf++) rte_pktmbuf_free(bufs[buf]);
            }
        }
    }
}


void btree_init(string filepath, bmap &bt, int max_offload_prefixes,
                AgentClient *agent) {
    /* Create KV database */
    vector<tuple<KeyType, ValueType, size_t>> dataset;
    if (!filepath.empty()) {
        readDatabase(dataset, filepath);  // unsorted
    } else {
        dataset = {
            {12, 1212, 2}, {15, 1515, 1}, {8, 8888, 1}, {4, 4444, 1}, {5, 5555, 1},
            {1, 1111, 1},  {2, 2222, 1},  {3, 3333, 2}, {6, 6666, 5}, {7, 7777, 4},
        };
    };

    vector<pair<KeyType, ValueType>> kv_sorted;
    std::unordered_map<KeyType, size_t> key_to_freq;
    for (const auto &tp : dataset) {
        kv_sorted.emplace_back(std::get<0>(tp), std::get<1>(tp));
        key_to_freq[std::get<0>(tp)] = std::get<2>(tp);
    }
    sort(kv_sorted.begin(), kv_sorted.end());  // sort by key

    // Organize the database into a B+ tree
    bt.bulk_load(kv_sorted.begin(), kv_sorted.end());
    printf("stx btree: size %zu, layers %u\n", bt.size(), bt.tree.m_root->level + 1);

    // Init solver
    Solver solver;
    solver.key_to_freq = key_to_freq;
    std::vector<std::pair<ternary_t, bt_node_t*>> offload_lpms = solver.solve(bt.tree.m_root, max_offload_prefixes);

    std::vector<PrefixEntryWithPtr> offload_lpms_with_key;
    for (auto [t, pt] : offload_lpms)
        offload_lpms_with_key.push_back(PrefixEntryWithPtr(t.key, (int)t.prefix_len(), (uint64_t)pt));

    if (agent) {
        printf("calling agent\n");
        agent->UpdatePrefixEntries({}, offload_lpms_with_key);
    } else {
        printf("writing to lpm_offloading_cmds.txt\n");
        FILE *fp = fopen(LPM_TXT_FILEPATH, "w");
        if (!fp) {
#ifndef LOCAL_TEST
            rte_exit(EXIT_FAILURE, "cannot open lpm_offloading_cmds.txt\n");
#else
            exit(-1);
#endif
        }
        const char *tablename = "bfrt.kvp_cache_tcam.pipe.Ingress.kvp_cache.cache_tcam";
        fprintf(fp, "%s.clear()\n", tablename);
        for (const PrefixEntryWithPtr &lpm : offload_lpms_with_key) {
            fprintf(fp, "%s.add_with_lpm_hit(%#" PRIx64 ", %d, %#" PRIx64 ")\n", tablename,
                    lpm.prefix, lpm.prefix_length, lpm.pointer);
        }
        fclose(fp);
    }
}

int main(int argc, char *argv[]) {
#ifndef LOCAL_TEST
    struct rte_mempool *mbuf_pool;
    unsigned nb_ports;
    uint16_t portid;

    /* Initialize the Environment Abstraction Layer (EAL). */
    int ret = rte_eal_init(argc, argv);
    if (ret < 0) rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    argc -= ret;
    argv += ret;

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count_avail();
    printf("nb_ports=%u\n", nb_ports);
    // if (nb_ports < 2 || (nb_ports & 1))
    //     rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

    /* Creates a new mempool in memory to hold the mbufs. */
    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports, MBUF_CACHE_SIZE, 0,
                                        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool == NULL) rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

    /* Initialize all ports. */
    RTE_ETH_FOREACH_DEV(portid)
    if (port_init(portid, mbuf_pool) != 0)
        rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", portid);

    if (rte_lcore_count() > 1) printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");
#endif

    /* Parse arguments */
    std::string dataset_path;
    int max_offload_prefixes = 0;
    AgentClient *agent = nullptr;
    std::thread cq_thread;
    if (argc > 1) 
        dataset_path = argv[1];
    if (argc > 2) 
        max_offload_prefixes = atoi(argv[2]);

    bmap bt;

    if (argc > 3) {
        agent = new AgentClient(grpc::CreateChannel(argv[3], grpc::InsecureChannelCredentials()));
        cq_thread = std::thread(&AgentClient::AsyncCompleteRpc, agent);
    }

    btree_init(dataset_path, bt, max_offload_prefixes, agent);

#ifndef LOCAL_TEST
    system("touch server_started");
    fflush(stdout);
    
    lcore_main(bt, agent);
#endif

    if (agent) {
        cq_thread.join();
        delete agent;
    }

    /* clean up the EAL */
#ifndef LOCAL_TEST
    rte_eal_cleanup();
#endif

    return 0;
}
