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
#define BURST_SIZE 32

static const struct rte_eth_conf port_conf_default = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_NONFRAG_IPV4_UDP,
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

static int
lcore_rx(struct lcore_params *p)
{
	const uint16_t nb_ports = rte_eth_dev_count_avail();
	const int socket_id = rte_socket_id();
	uint16_t port;
	struct rte_mbuf *bufs[BURST_SIZE*2];

	RTE_ETH_FOREACH_DEV(port) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0)
			continue;

		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) != socket_id)
			printf("WARNING, port %u is on remote NUMA node to "
					"RX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("\nCore %u doing packet RX.\n", rte_lcore_id());
	port = 0;
	while (!quit_signal_rx) {

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}
		const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs,
				BURST_SIZE);
		if (unlikely(nb_rx == 0)) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}
		app_stats.rx.rx_pkts += nb_rx;

/*
 * You can run the distributor on the rx core with this code. Returned
 * packets are then send straight to the tx core.
 */
#if 0
	rte_distributor_process(d, bufs, nb_rx);
	const uint16_t nb_ret = rte_distributor_returned_pktsd,
			bufs, BURST_SIZE*2);

		app_stats.rx.returned_pkts += nb_ret;
		if (unlikely(nb_ret == 0)) {
			if (++port == nb_ports)
				port = 0;
			continue;
		}

		struct rte_ring *tx_ring = p->dist_tx_ring;
		uint16_t sent = rte_ring_enqueue_burst(tx_ring,
				(void *)bufs, nb_ret, NULL);
#else
		uint16_t nb_ret = nb_rx;
		/*
		 * Swap the following two lines if you want the rx traffic
		 * to go directly to tx, no distribution.
		 */
		struct rte_ring *out_ring = p->rx_dist_ring;
		/* struct rte_ring *out_ring = p->dist_tx_ring; */

		uint16_t sent = rte_ring_enqueue_burst(out_ring,
				(void *)bufs, nb_ret, NULL);
#endif

		app_stats.rx.enqueued_pkts += sent;
		if (unlikely(sent < nb_ret)) {
			app_stats.rx.enqdrop_pkts +=  nb_ret - sent;
			RTE_LOG_DP(DEBUG, DISTRAPP,
				"%s:Packet loss due to full ring\n", __func__);
			while (sent < nb_ret)
				rte_pktmbuf_free(bufs[sent++]);
		}
		if (++port == nb_ports)
			port = 0;
	}
	/* set worker & tx threads quit flag */
	printf("\nCore %u exiting rx task.\n", rte_lcore_id());
	quit_signal = 1;
	return 0;
}

static int
lcore_distributor(struct lcore_params *p)
{
	struct rte_ring *in_r = p->rx_dist_ring;
	struct rte_ring *out_r = p->dist_tx_ring;
	struct rte_mbuf *bufs[BURST_SIZE * 4];
	struct rte_distributor *d = p->d;

	printf("\nCore %u acting as distributor core.\n", rte_lcore_id());
	while (!quit_signal_dist) {
		const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
				(void *)bufs, BURST_SIZE*1, NULL);
		if (nb_rx) {
			app_stats.dist.in_pkts += nb_rx;

			/* Distribute the packets */
			rte_distributor_process(d, bufs, nb_rx);
			/* Handle Returns */
			const uint16_t nb_ret =
				rte_distributor_returned_pkts(d,
					bufs, BURST_SIZE*2);

			if (unlikely(nb_ret == 0))
				continue;
			app_stats.dist.ret_pkts += nb_ret;

			uint16_t sent = rte_ring_enqueue_burst(out_r,
					(void *)bufs, nb_ret, NULL);
			app_stats.dist.sent_pkts += sent;
			if (unlikely(sent < nb_ret)) {
				app_stats.dist.enqdrop_pkts += nb_ret - sent;
				RTE_LOG(DEBUG, DISTRAPP,
					"%s:Packet loss due to full out ring\n",
					__func__);
				while (sent < nb_ret)
					rte_pktmbuf_free(bufs[sent++]);
			}
		}
	}
	printf("\nCore %u exiting distributor task.\n", rte_lcore_id());
	quit_signal_work = 1;

	rte_distributor_flush(d);
	/* Unblock any returns so workers can exit */
	rte_distributor_clear_returns(d);
	quit_signal_rx = 1;
	return 0;
}

static int
lcore_worker(struct lcore_params *p)
{
	struct rte_distributor *d = p->d;
	const unsigned id = p->worker_id;
	unsigned int num = 0;
	unsigned int i;

	/*
	 * for single port, xor_val will be zero so we won't modify the output
	 * port, otherwise we send traffic from 0 to 1, 2 to 3, and vice versa
	 */
	const unsigned xor_val = (rte_eth_dev_count_avail() > 1);
	struct rte_mbuf *buf[8] __rte_cache_aligned;

	for (i = 0; i < 8; i++)
		buf[i] = NULL;

	app_stats.worker_pkts[p->worker_id] = 1;

	printf("\nCore %u acting as worker core.\n", rte_lcore_id());
	while (!quit_signal_work) {
		num = rte_distributor_get_pkt(d, id, buf, buf, num);
		/* Do a little bit of work for each packet */
		for (i = 0; i < num; i++) {
			uint64_t t = rte_rdtsc()+100;

			while (rte_rdtsc() < t)
				rte_pause();
			buf[i]->port ^= xor_val;
		}

		app_stats.worker_pkts[p->worker_id] += num;
		if (num > 0)
			app_stats.worker_bursts[p->worker_id][num-1]++;
	}
	return 0;
}

static int
lcore_tx(struct rte_ring *in_r)
{
	static struct output_buffer tx_buffers[RTE_MAX_ETHPORTS];
	const int socket_id = rte_socket_id();
	uint16_t port;

	RTE_ETH_FOREACH_DEV(port) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << port)) == 0)
			continue;

		if (rte_eth_dev_socket_id(port) > 0 &&
				rte_eth_dev_socket_id(port) != socket_id)
			printf("WARNING, port %u is on remote NUMA node to "
					"TX thread.\n\tPerformance will not "
					"be optimal.\n", port);
	}

	printf("\nCore %u doing packet TX.\n", rte_lcore_id());
	while (!quit_signal) {

		RTE_ETH_FOREACH_DEV(port) {
			/* skip ports that are not enabled */
			if ((enabled_port_mask & (1 << port)) == 0)
				continue;

			struct rte_mbuf *bufs[BURST_SIZE_TX];
			const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
					(void *)bufs, BURST_SIZE_TX, NULL);
			app_stats.tx.dequeue_pkts += nb_rx;

			/* if we get no traffic, flush anything we have */
			if (unlikely(nb_rx == 0)) {
				flush_all_ports(tx_buffers);
				continue;
			}

			/* for traffic we receive, queue it up for transmit */
			uint16_t i;
			rte_prefetch_non_temporal((void *)bufs[0]);
			rte_prefetch_non_temporal((void *)bufs[1]);
			rte_prefetch_non_temporal((void *)bufs[2]);
			for (i = 0; i < nb_rx; i++) {
				struct output_buffer *outbuf;
				uint8_t outp;
				rte_prefetch_non_temporal((void *)bufs[i + 3]);
				/*
				 * workers should update in_port to hold the
				 * output port value
				 */
				outp = bufs[i]->port;
				/* skip ports that are not enabled */
				if ((enabled_port_mask & (1 << outp)) == 0)
					continue;

				outbuf = &tx_buffers[outp];
				outbuf->mbufs[outbuf->count++] = bufs[i];
				if (outbuf->count == BURST_SIZE_TX)
					flush_one_port(outbuf, outp);
			}
		}
	}
	printf("\nCore %u exiting tx task.\n", rte_lcore_id());
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

	if (rte_lcore_count() > 1)
		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

    // 声明两个环形无锁队列用于数据传输
	rx_dist_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_dist_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

    dist_tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (dist_tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

    // 0号lcore运行rx线程
    struct lcore_params *p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){rx_dist_ring, dist_tx_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_rx, p, 0);

    // 1号运行distributor线程
    p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){rx_dist_ring, dist_tx_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_distributor, p, 1);
    p = rte_malloc(NULL, sizeof(*p), 0);

    // 2号到5号lcore运行worker线程
    p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){rx_dist_ring, dist_tx_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_worker, p, 2);
    p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){rx_dist_ring, dist_tx_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_worker, p, 3);
    p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){rx_dist_ring, dist_tx_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_worker, p, 4);
    p = rte_malloc(NULL, sizeof(*p), 0);
    if (!p)
        rte_panic("malloc failure\n");
    *p = (struct lcore_params){rx_dist_ring, dist_tx_ring, mbuf_pool};
    rte_eal_remote_launch((lcore_function_t *)lcore_worker, p, 5);

    // 6号lcore运行tx线程
    rte_eal_remote_launch((lcore_function_t *)lcore_tx, dist_tx_ring, 6);

    // wait for ending.
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}

	return 0;
}
