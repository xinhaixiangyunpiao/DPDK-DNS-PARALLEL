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

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define NUM_QUEUES 4

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP | ETH_RSS_TCP | ETH_RSS_UDP,
		},
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
	const uint16_t rx_rings = NUM_QUEUES, tx_rings = NUM_QUEUES;
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


/*
 * The lcore main. This is the main thread that does the work, read
 * an query packet and write an reply packet.
 */
static void
lcore_main_loop(void)
{
	uint16_t port = 0;	        // only one port is used.
    unsigned lcore_id;
	struct rte_mbuf *query_buf[BURST_SIZE], *reply_buf[BURST_SIZE];
	uint16_t nb_rx, nb_tx;
	uint8_t *buffer;
	struct Message msg;
	memset(&msg, 0, sizeof(struct Message));
	
    lcore_id = rte_lcore_id(); // get lcore id 

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
	
	printf("\nSimpleDNS (using DPDK) is running...\n");

    int total_rx = 0;
    int total_tx = 0;
	/* Run until the application is quit or killed. */
	while (!force_quit) {
		// Add your code here.
		// Part 0. 

		// ask for reply packet memory
		for(int i = 0; i < BURST_SIZE; i++){
			do{
				reply_buf[i] = rte_pktmbuf_alloc(mbuf_pool);
			}while(reply_buf[i] == NULL);
		}
		
		/*********preparation (begin)**********/
		/*********preparation (end)**********/
		
		// Add your code here.
		// Part 1.
		// receive to query_buf and assign value to buffer. 0号核接收0号队列，1号核接收1号队列...
		nb_rx = rte_eth_rx_burst(port, lcore_id, query_buf, BURST_SIZE);

		if (unlikely(nb_rx == 0)){
			for(int i = 0; i < BURST_SIZE; i++)
				rte_pktmbuf_free(reply_buf[i]);
			continue;
		}
		
		int cnt = 0;
		for(int i = 0; i < nb_rx; i++){

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
			rte_pktmbuf_append(reply_buf[cnt], sizeof(struct ether_hdr));
			rte_pktmbuf_append(reply_buf[cnt], sizeof(struct ipv4_hdr));
			rte_pktmbuf_append(reply_buf[cnt], sizeof(struct udp_hdr));
			
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
			char * payload = (char*)rte_pktmbuf_append(reply_buf[cnt], buflen);
			rte_memcpy(payload, buffer, buflen);
			
			// acording to query_buf, build DPDK packet head
			build_packet(rte_pktmbuf_mtod_offset(query_buf[i], char*, 0), rte_pktmbuf_mtod_offset(reply_buf[cnt], char*, 0), buflen);
			cnt++;
		}
		
        // send packet. 0号核发送到0号queue，1号核发送到1号queue
		nb_tx = rte_eth_tx_burst(port, lcore_id, reply_buf, cnt);
	   
        total_rx += nb_rx;
        total_tx += nb_tx;
        
		// free query buffer and unsend packet.
		for(int i = 0; i < nb_rx; i++){
			rte_pktmbuf_free(query_buf[i]);
			if(nb_tx < nb_rx){
				for(uint8_t j = nb_tx; j < nb_rx; j++)
				rte_pktmbuf_free(reply_buf[j]);
			}
		}
	}
    
    // printf result
    printf("core id: %d nb_rx:%d, nb_tx:%d\n", lcore_id, total_rx, total_tx); 
}

static int
dns_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	lcore_main_loop();
	return 0;
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

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(dns_launch_one_lcore, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	return 0;
}