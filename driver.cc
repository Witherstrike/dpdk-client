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
int dpdk_driver::port_init(uint16_t port, uint16_t rx_rings,
                           uint16_t tx_rings) {
  struct rte_eth_conf port_conf; // = port_conf_default;
  uint16_t nb_rxd = RX_RING_SIZE;
  uint16_t nb_txd = TX_RING_SIZE;
  int retval;
  uint16_t q;
  struct rte_eth_dev_info dev_info;
  struct rte_eth_txconf txconf;

  if (!rte_eth_dev_is_valid_port(port))
    return -1;

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
        port, q, nb_rxd, rte_eth_dev_socket_id(port), NULL, mbuf_pool[q]);
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

void dpdk_driver::register_queue_id() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (map_queue_id.count(std::this_thread::get_id()) == 0) {
    map_queue_id[std::this_thread::get_id()] = map_queue_id.size();
  }
}

uint16_t dpdk_driver::get_queue_id() {
  return map_queue_id[std::this_thread::get_id()];
}

void dpdk_driver::register_dest_port() {
  std::lock_guard<std::mutex> lock(mutex_);
  if (map_dest_port.count(std::this_thread::get_id()) == 0) {
    map_dest_port[std::this_thread::get_id()] = map_dest_port.size();
  }
}

uint16_t dpdk_driver::get_dest_port() {
  return map_dest_port[std::this_thread::get_id()];
}

uint16_t dpdk_driver::send_multi(uint16_t nb_packets, char **contexts, unsigned *nb_bytes, uint16_t send_no, 
                             uint16_t queue_id) {
  uint16_t port = PORT_USED;
  
  struct rte_mbuf *bufs[BURST_SIZE];

  struct rte_ether_hdr *hdr_eth;
  struct rte_ipv4_hdr *hdr_ip;
  struct rte_udp_hdr *hdr_udp;

  for (uint16_t i = 0; i < nb_packets; i++) {
    bufs[i] = rte_pktmbuf_alloc(mbuf_pool[queue_id]);

    char *payload = rte_pktmbuf_append(bufs[i], nb_bytes[i]);
    if (payload == NULL) {
      rte_exit(EXIT_FAILURE, "Error with rte_pktmbuf_append\n");
    }

    rte_memcpy(payload, contexts[i], nb_bytes[i]);

    hdr_udp = (struct rte_udp_hdr *)rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_udp_hdr));
    hdr_udp->src_port = htons(0);
    hdr_udp->dst_port = htons(send_no); // we use udp's src_port to carry no.
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

    hdr_eth = (struct rte_ether_hdr *)rte_pktmbuf_prepend(bufs[i], sizeof(struct rte_ether_hdr));
    memset(&hdr_eth->src_addr, 0x0, RTE_ETHER_ADDR_LEN);
    memset(&hdr_eth->dst_addr, 0x0, RTE_ETHER_ADDR_LEN);
    hdr_eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    hdr_udp->dgram_cksum = rte_ipv4_udptcp_cksum(hdr_ip, hdr_udp);
    hdr_ip->hdr_checksum = rte_ipv4_cksum(hdr_ip);
  }

  uint16_t nb_tx = rte_eth_tx_burst(port, queue_id, bufs, nb_packets);
  if (unlikely(nb_tx < nb_packets)) {
    uint16_t buf;
    for (buf = nb_tx; buf < nb_packets; buf++) rte_pktmbuf_free(bufs[buf]);
  }

  return nb_tx;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */
void dpdk_driver::send_pkt(char *context, unsigned nb_bytes, uint16_t send_no,
                           uint16_t queue_id) {
  uint16_t port = PORT_USED;

  /* Get burst of RX packets, from first port of pair. */
  struct rte_mbuf *mbuf;

  struct rte_ether_hdr *hdr_eth;
  struct rte_ipv4_hdr *hdr_ip;
  struct rte_udp_hdr *hdr_udp;

  mbuf = rte_pktmbuf_alloc(mbuf_pool[queue_id]);

  char *payload = rte_pktmbuf_append(mbuf, nb_bytes);
  if (payload == NULL) {
    rte_exit(EXIT_FAILURE, "Error with rte_pktmbuf_append\n");
  }

  rte_memcpy(payload, context, nb_bytes);

  hdr_udp = (struct rte_udp_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_udp_hdr));
  hdr_udp->src_port = htons(0);
  hdr_udp->dst_port = htons(send_no); // we use udp's src_port to carry no.
  hdr_udp->dgram_len = htons(nb_bytes + sizeof(struct rte_udp_hdr));
  hdr_udp->dgram_cksum = 0;

  hdr_ip =
      (struct rte_ipv4_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ipv4_hdr));
  hdr_ip->version_ihl = 0x45;
  hdr_ip->type_of_service = 0;
  hdr_ip->total_length =
      htons(nb_bytes + sizeof(struct rte_udp_hdr) + sizeof(struct rte_ipv4_hdr));
  hdr_ip->packet_id = 0;
  hdr_ip->fragment_offset = 0;
  hdr_ip->time_to_live = 64;
  hdr_ip->next_proto_id = IPPROTO_UDP;
  hdr_ip->hdr_checksum = 0;
  hdr_ip->src_addr = htonl(0);
  hdr_ip->dst_addr = htonl(0);

  hdr_eth =
      (struct rte_ether_hdr *)rte_pktmbuf_prepend(mbuf, sizeof(struct rte_ether_hdr));
  memset(&hdr_eth->src_addr, 0x0, RTE_ETHER_ADDR_LEN);
  memset(&hdr_eth->dst_addr, 0x0, RTE_ETHER_ADDR_LEN);
  hdr_eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

  hdr_udp->dgram_cksum = rte_ipv4_udptcp_cksum(hdr_ip, hdr_udp);
  hdr_ip->hdr_checksum = rte_ipv4_cksum(hdr_ip);

  /* Send burst of TX packets, to second port of pair. */
  uint16_t nb_tx = rte_eth_tx_burst(port, queue_id, &mbuf, 1);

  /* Free any unsent packets. */
  if (unlikely(nb_tx < 1)) {
    rte_pktmbuf_free(mbuf);
  }
}

uint16_t dpdk_driver::recv_multi(uint16_t nb_packets, char **contexts, unsigned *nb_bytes, uint16_t *recv_no, 
                                 uint16_t queue_id) {
  uint16_t port = PORT_USED;

  struct rte_mbuf *bufs[BURST_SIZE];

  struct rte_ether_hdr *hdr_eth;
  struct rte_ipv4_hdr *hdr_ip;
  struct rte_udp_hdr *hdr_udp;

  uint16_t nb_rx;
  do {
    nb_rx = rte_eth_rx_burst(port, queue_id, bufs, BURST_SIZE); // !!!!!!!!!!!!!!!!!!!!!!!!! <4 won't work, I don't know why !!!!!!!!!!!!!!!!!!!!!!!!!
  } while (unlikely(nb_rx < 1));

  uint16_t nb_process = std::min(nb_rx, nb_packets);
  for (uint16_t i = 0; i < nb_process; i++) {
    hdr_eth = rte_pktmbuf_mtod(bufs[i], struct rte_ether_hdr *);

    hdr_ip = (struct rte_ipv4_hdr *)(hdr_eth + 1);

    hdr_udp = (struct rte_udp_hdr *)(hdr_ip + 1);
    recv_no[i] = htons(hdr_udp->dst_port);

    char *payload = (char *)(hdr_udp + 1);

    rte_memcpy(contexts[i], payload, nb_bytes[i]);

    rte_pktmbuf_free(bufs[i]);
  } 
  for (uint16_t i = nb_process; i < nb_rx; i++) {
    rte_pktmbuf_free(bufs[i]);
  }

  return nb_rx;
}

void dpdk_driver::recv_pkt(char *context, unsigned nb_bytes, uint16_t &recv_no,
                           uint16_t queue_id) {
  uint16_t port = PORT_USED;

  /* Get burst of RX packets, from first port of pair. */
  struct rte_mbuf *mbuf;

  struct rte_ether_hdr *hdr_eth;
  struct rte_ipv4_hdr *hdr_ip;
  struct rte_udp_hdr *hdr_udp;

  /* Send burst of TX packets, to second port of pair. */
  uint16_t nb_rx;

  /* Free any unsent packets. */
  do {
    nb_rx = rte_eth_rx_burst(port, queue_id, &mbuf, 4); // !!!!!!!!!!!!!!!!!!!!!!!!! <4 won't work, I don't know why !!!!!!!!!!!!!!!!!!!!!!!!!
  } while (unlikely(nb_rx < 1));

  hdr_eth = rte_pktmbuf_mtod(mbuf, struct rte_ether_hdr *);

  hdr_ip = (struct rte_ipv4_hdr *)(hdr_eth + 1);

  hdr_udp = (struct rte_udp_hdr *)(hdr_ip + 1);
  recv_no = htons(hdr_udp->dst_port);

  char *payload = (char *)(hdr_udp + 1);

  rte_memcpy(context, payload, nb_bytes);

  rte_pktmbuf_free(mbuf);
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int dpdk_driver::init(int argc, char *argv[], int nb_threads) {
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
  nb_queues = nb_threads;
  for (q = 0; q < nb_queues; ++q) {
    mbuf_pool[q] = rte_pktmbuf_pool_create(
        (std::string("MBUF_POOL") + std::to_string(q)).c_str(), NUM_MBUFS,
        MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if (mbuf_pool[q] == NULL)
      rte_exit(EXIT_FAILURE, "Cannot create mbuf pool %" PRIu16 "\n", q);
  }

  /* Initialize all ports. */
  if (port_init(port, nb_queues, nb_queues) != 0)
    rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 "\n", port);

  return ret;
}

void dpdk_driver::flow_init(uint16_t queue_id, uint16_t dest_port) {
  struct rte_flow *flow;
  struct rte_flow_error error;
  uint16_t port = PORT_USED;

  printf("dpdk::driver::flow_init(queue_id: %d, dest_port: %d)\n", queue_id,
         dest_port);

  /* create flow for send packet with */
  flow = generate_udp_flow(port, queue_id, 0x0, EMPTY_IP_MASK, 0x0,
                           EMPTY_IP_MASK, dest_port, FULL_PORT_MASK, 0x0,
                           EMPTY_PORT_MASK, &error);
  if (!flow) {
    printf("Flow can't be created %d message: %s\n", error.type,
           error.message ? error.message : "(no stated reason)");
    rte_exit(EXIT_FAILURE, "error in creating flow");
  }
}
