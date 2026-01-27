/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#include "driver.h"
#include <iostream>

#define PORT_USED 0
#define BURST_SIZE 32

using namespace std;
// #define DEBUG

/* basicfwd.c: Basic DPDK skeleton forwarding example. */

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
int dpdk_driver::port_init(uint16_t port) {
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
  for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(
        port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool);
    if (retval < 0)
      return retval;
  }

  txconf = dev_info.default_txconf;
  txconf.offloads = port_conf.txmode.offloads;
  /* Allocate and set up 1 TX queue per Ethernet port. */
  for (q = 0; q < tx_rings; q++) {
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

uint16_t dpdk_driver::send_multi(uint16_t nb_packets, char **contexts, unsigned *nb_bytes) {
  uint16_t port = PORT_USED;
  
  struct rte_mbuf *bufs[BURST_SIZE];

  struct rte_ether_hdr *hdr_eth;
  struct rte_ipv4_hdr *hdr_ip;
  struct rte_udp_hdr *hdr_udp;

  for (uint16_t i = 0; i < nb_packets; i++) {
    bufs[i] = rte_pktmbuf_alloc(mbuf_pool);

    char *payload = rte_pktmbuf_append(bufs[i], nb_bytes[i]);
    if (payload == NULL) {
      rte_exit(EXIT_FAILURE, "Error with rte_pktmbuf_append\n");
    }

    rte_memcpy(payload, contexts[i], nb_bytes[i]);

    hdr_udp = (struct rte_udp_hdr *)rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_udp_hdr));
    hdr_udp->src_port = htons(0);
    hdr_udp->dst_port = htons(0); // we use udp's src_port to carry no.
    hdr_udp->dgram_len = htons(nb_bytes[i] + sizeof(struct rte_udp_hdr));
    hdr_udp->dgram_cksum = 0;

    hdr_ip = (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_ipv4_hdr));
    hdr_ip->version_ihl = 0x45;
    hdr_ip->type_of_service = 0;
    hdr_ip->total_length =
        htons(nb_bytes[i] + sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr));
    hdr_ip->packet_id = 0;
    hdr_ip->fragment_offset = 0;
    hdr_ip->time_to_live = 64;
    hdr_ip->next_proto_id = IPPROTO_UDP;
    hdr_ip->hdr_checksum = 0;
    hdr_ip->src_addr = htonl(0);
    hdr_ip->dst_addr = htonl(0);

    hdr_ip->hdr_checksum = rte_ipv4_cksum(hdr_ip);
  }

  uint16_t nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_packets);
  if (unlikely(nb_tx < nb_packets)) {
    uint16_t buf;
    for (buf = nb_tx; buf < nb_packets; buf++) rte_pktmbuf_free(bufs[buf]);
  }

  return nb_tx;
}

uint16_t dpdk_driver::recv_multi(char **contexts, unsigned *nb_bytes) {
  uint16_t port = PORT_USED;

  struct rte_mbuf *bufs[BURST_SIZE];

  struct rte_ether_hdr *hdr_eth;
  struct rte_ipv4_hdr *hdr_ip;
  struct rte_udp_hdr *hdr_udp;

  uint16_t nb_rx;
  nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE); // !!!!!!!!!!!!!!!!!!!!!!!!! <4 won't work, I don't know why !!!!!!!!!!!!!!!!!!!!!!!!!

  for (uint16_t i = 0; i < nb_rx; i++) {
    hdr_eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);

    hdr_ip = (struct rte_ipv4_hdr *)(hdr_eth + 1);

    char *payload = (char *)(hdr_ip + 1);

    rte_memcpy(contexts[i], payload, nb_bytes[i]);

    rte_pktmbuf_free(bufs[i]);
  }

  return nb_rx;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int dpdk_driver::init(int argc, char *argv[]) {
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
  if (port_init(port) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port);

  return ret;
}
