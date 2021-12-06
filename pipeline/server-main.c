#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_debug.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <stdbool.h>
#include <inttypes.h>
#include <signal.h>

#include "SimpleDNS.h"

static volatile bool force_quit;

#define RX_RING_SIZE 4096
#define TX_RING_SIZE 4096

#define SCHED_RX_RING_SZ 8192
#define SCHED_TX_RING_SZ 8192

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 64
#define PROCESS_SIZE 4

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.max_rx_pkt_len = ETHER_MAX_LEN,
	},
};
struct rte_mempool *mbuf_pool;

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = port_conf_default;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	rte_eth_dev_info_get(port, &dev_info);
	if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			DEV_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
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
	struct ether_addr addr;
	rte_eth_macaddr_get(port, &addr);
	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port,
			addr.addr_bytes[0], addr.addr_bytes[1],
			addr.addr_bytes[2], addr.addr_bytes[3],
			addr.addr_bytes[4], addr.addr_bytes[5]);

	/* Enable RX in promiscuous mode for the Ethernet device. */
	rte_eth_promiscuous_enable(port);

	return 0;
}

/*
 * In this function we complete the headers of a answer packet(buf1), 
 * basing on information from the query packet(buf2).
 */
static void
build_packet(char *buf1, char * buf2, uint16_t pkt_size)
{
	struct ether_hdr *eth_hdr1, *eth_hdr2;
	struct ipv4_hdr *ip_hdr1, *ip_hdr2;
	struct udp_hdr *udp_hdr1, *udp_hdr2;

	// Add your code here.
	// Part 4.

	// put every point to the correct position
	eth_hdr1 = (struct ether_hdr*)buf1;
	ip_hdr1 = (struct ipv4_hdr*)(buf1 + 14);
	udp_hdr1 = (struct udp_hdr*)(buf1 + 14 + 20);
	eth_hdr2 = (struct ether_hdr*)buf2;
	ip_hdr2 = (struct ipv4_hdr*)(buf2 + 14);
	udp_hdr2 = (struct udp_hdr*)(buf2 + 14 + 20);

	// acordding to the query packet head to fill the reply packet head.

	/** ether head
     * struct ether_addr 	d_addr
     * struct ether_addr 	s_addr
     * uint16_t ether_type
     **/
	eth_hdr2->d_addr = eth_hdr1->s_addr;
	eth_hdr2->s_addr = eth_hdr1->d_addr;
	eth_hdr2->ether_type = eth_hdr1->ether_type;

	/** ipv4 head
        uint8_t 	version_ihl
        uint8_t 	type_of_service
        uint16_t 	total_length
        uint16_t 	packet_id
        uint16_t 	fragment_offset
        uint8_t 	time_to_live
        uint8_t 	next_proto_id
        uint16_t 	hdr_checksum
        uint32_t 	src_addr
        uint32_t 	dst_addr
    **/
	ip_hdr2->version_ihl = ip_hdr1->version_ihl;
	ip_hdr2->type_of_service = ip_hdr1->type_of_service;
	ip_hdr2->total_length = rte_cpu_to_be_16(28 + pkt_size);
	ip_hdr2->packet_id = ip_hdr1->packet_id ^ 0x0100;
	ip_hdr2->fragment_offset = ip_hdr1->fragment_offset | (0x0040);
	ip_hdr2->time_to_live = ip_hdr1->time_to_live;
	ip_hdr2->next_proto_id = ip_hdr1->next_proto_id;
	ip_hdr2->hdr_checksum = 0;
	ip_hdr2->src_addr = ip_hdr1->dst_addr;
	ip_hdr2->dst_addr = ip_hdr1->src_addr;
	ip_hdr2->hdr_checksum = rte_ipv4_cksum(ip_hdr2);

	/** udp head
        uint16_t 	src_port
        uint16_t 	dst_port
        uint16_t 	dgram_len
        uint16_t 	dgram_cksum
    **/
	udp_hdr2->src_port = udp_hdr1->dst_port;
	udp_hdr2->dst_port = udp_hdr1->src_port;
	udp_hdr2->dgram_len = rte_cpu_to_be_16(8 + pkt_size);
	udp_hdr2->dgram_cksum = 0;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}

struct lcore_params {
	struct rte_ring *rx_ring;
	struct rte_ring *tx_ring;
};

static int
lcore_rx(struct rte_ring *rx_ring)
{
	uint16_t port;
	uint16_t nb_rx, nb_tx;
	struct rte_mbuf *bufs[BURST_SIZE];

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	if (rte_eth_dev_socket_id(port) > 0 &&
			rte_eth_dev_socket_id(port) !=
					(int)rte_socket_id())
		printf("WARNING, port %u is on remote NUMA node to "
				"polling thread.\n\tPerformance will "
				"not be optimal.\n", port);

	printf("\nCore %u doing packet RX.\n", rte_lcore_id());

	port = 0;
	uint32_t rx_queue_drop_packets = 0;
	while (!force_quit){
		// 从port接收包
		nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);

		// 批量enqueue到rx_ring中
		nb_tx = rte_ring_enqueue_burst(rx_ring, (void *)bufs, nb_rx, NULL);

		// 释放没入队的包
		if(unlikely(nb_tx < nb_rx)){
			rx_queue_drop_packets += nb_rx - nb_tx;
			while(nb_tx < nb_rx){
				rte_pktmbuf_free(bufs[nb_tx++]);
			}
		}
	}
	printf("rx queue drop packet number: %d\n", rx_queue_drop_packets);

	return 0;
}

static int
lcore_worker(struct lcore_params *p)
{
	uint16_t nb_rx, nb_tx;
	uint16_t i = 0;
	struct rte_mbuf *query_buf[PROCESS_SIZE], *reply_buf[PROCESS_SIZE];
	struct rte_ring *in_ring = p->rx_ring;
	struct rte_ring *out_ring = p->tx_ring;
	uint8_t *buffer;
	struct Message msg;
	memset(&msg, 0, sizeof(struct Message));

	printf("\nCore %u doing packet processing.\n", rte_lcore_id());

	uint16_t tx_queue_drop_packets = 0;

	while (!force_quit) {
		// apply reply packet memory
		for(i = 0; i < PROCESS_SIZE; i++){
			do{
				reply_buf[i] = rte_pktmbuf_alloc(mbuf_pool);
			}while(reply_buf[i] == NULL);
		}

		// dequeue 4 packet
		nb_rx = rte_ring_dequeue_burst(in_ring, (void *)query_buf, PROCESS_SIZE, NULL);

		if (unlikely(nb_rx == 0)){
			for(i = 0; i < PROCESS_SIZE; i++)
				rte_pktmbuf_free(reply_buf[i]);
			continue;
		}

		uint16_t nb_tx_prepare = 0;
		for(i = 0; i < nb_rx; i++){
            free_questions(msg.questions);
            free_resource_records(msg.answers);
            free_resource_records(msg.authorities);
            free_resource_records(msg.additionals);
            memset(&msg, 0, sizeof(struct Message));

			// filter the port 9000 not 9000
			if(*rte_pktmbuf_mtod_offset(query_buf[i], uint16_t*, 36) != rte_cpu_to_be_16(9000)){
				continue;
			}

			// assign the data start address to buffer
			buffer = rte_pktmbuf_mtod_offset(query_buf[i], uint8_t*, 42); // 14 + 20 + 8 = 42
			
			/*********read input (begin)**********/ 
			// not DNS
			if (decode_msg(&msg, buffer, query_buf[i]->data_len - 42) != 0) {
				continue;
			}
			/* Print query */
			//print_query(&msg);

			resolver_process(&msg);
			/* Print response */
			//print_query(&msg);
			/*********read input (end)**********/
			
			//Add your code here.
			//Part 2.

			// plan the reply packet space.
			// add ethernet header, ipv4 header, udp header
			rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct ether_hdr));
			rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct ipv4_hdr));
			rte_pktmbuf_append(reply_buf[nb_tx_prepare], sizeof(struct udp_hdr));
			
			/*********write output (begin)**********/
			uint8_t *p = buffer;
			if (encode_msg(&msg, &p) != 0) {
				continue;
			}

			uint32_t buflen = p - buffer;
			/*********write output (end)**********/
			
			//Add your code here.
			//Part 3.

			// add the payload
			char * payload = (char*)rte_pktmbuf_append(reply_buf[nb_tx_prepare], buflen);
			rte_memcpy(payload, buffer, buflen);
			
			// acording to query_buf, build DPDK packet head
			build_packet(rte_pktmbuf_mtod_offset(query_buf[i], char*, 0), rte_pktmbuf_mtod_offset(reply_buf[nb_tx_prepare], char*, 0), buflen);
			nb_tx_prepare++;
		}

		// send to queue
		nb_tx = rte_ring_enqueue_burst(out_ring, (void *)reply_buf, nb_tx_prepare, NULL);

		// free query buffer and unsend packet.
		for(i = 0; i < nb_rx; i++)
			rte_pktmbuf_free(query_buf[i]);
		for(i = nb_tx; i < nb_tx_prepare; i++){
			tx_queue_drop_packets += 1;
			rte_pktmbuf_free(reply_buf[i]);
		}
	}
	
	printf("core %d: tx queue drop packet number: %d\n", rte_lcore_id(), tx_queue_drop_packets);

	return 0;
}

static int
lcore_tx(struct rte_ring *tx_ring)
{
	uint16_t port = 0;
	uint16_t nb_rx, nb_tx;
	struct rte_mbuf *bufs[BURST_SIZE];

	printf("\nCore %u doing packet TX.\n", rte_lcore_id());

	uint16_t dpdk_send_ring_drop_packets = 0;
	uint16_t total_sent = 0;
	while (!force_quit) {
		// dequeue data
		nb_rx = rte_ring_dequeue_burst(tx_ring, (void *)bufs, BURST_SIZE, NULL);

		// tx
		nb_tx = rte_eth_tx_burst(port, 0, bufs, nb_rx);
		total_sent += nb_tx;

		// free unsent memory
		if(unlikely(nb_tx < nb_rx)){
			dpdk_send_ring_drop_packets += nb_rx - nb_tx;
			while(nb_tx < nb_rx){
				rte_pktmbuf_free(bufs[nb_tx++]);
			}
		}
	}

	printf("dpdk send ring drop packet numbers: %d, total sent number: %d\n", dpdk_send_ring_drop_packets, total_sent);

	return 0;
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	unsigned lcore_id;
	uint16_t portid = 0, nb_ports = 1;

	/* Initialize the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	argc -= ret;
	argv += ret;

    force_quit = false;
    signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize port 0. */
	if (port_init(portid, mbuf_pool) != 0)
		rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n", portid);

    // 声明两个环形无锁队列用于数据传输
	struct rte_ring *rx_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

    struct rte_ring *tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

    // 0号lcore运行rx线程
	struct lcore_params p;
	p.rx_ring = rx_ring;
	p.tx_ring = tx_ring;
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if(lcore_id == 1)
			rte_eal_remote_launch((lcore_function_t*)lcore_tx, (void*)tx_ring, lcore_id);
		else
			rte_eal_remote_launch((lcore_function_t*)lcore_worker, (void*)&p, lcore_id);
	}
	// 0 lcore do RX. 
	lcore_rx(rx_ring);

    // wait for ending.
	rte_eal_mp_wait_lcore();

	// free memory
		/* waiting for filling.*/

	return 0;
}
