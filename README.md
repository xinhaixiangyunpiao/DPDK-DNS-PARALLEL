# DPDK-DNS-PARALLEL
网络算法学实验四参考代码

# 机器配置
## node5：
```
    CPU数：1
    核数：8
    逻辑核数：8
    内存：8GB
    万兆网卡信息：Intel X552/X557-AT * 2
    支持最大队列数量：63
    已使能队列数量：8 （可以通过ethtool -l eno3命令查看和更改）
    支持RSS类型：0x38d34 - 0011 1000 1101 0011 0100, 参考说明：https://www.cnblogs.com/yanhai307/p/10608323.html
```
## node6:
```
    CPU数：1
    核数：8
    逻辑核数：8
    内存：8GB
    万兆网卡信息：Intel X552/X557-AT * 2
    支持最大队列数量：63
    已使能队列数量：8 （可以通过ethtool -l eno3命令查看和更改）
    支持RSS类型：0x38d34 - 0011 1000 1101 0011 0100, 参考说明：https://www.cnblogs.com/yanhai307/p/10608323.html
```

# RTC(run to completion)
## 核心思路
1. 网卡配置多队列
2. 每个队列绑定一个核
3. 使用网卡自带的RSS或者Flow Director进行流的分类，最好使得网卡接收到的包均匀分散到不同队列里（负载均衡）

## 实现细节
1. 网卡配置多队列 <br/>
*ps: 参考代码：**skeleton** 和 **l2fwd***
> DPDK原生支持网卡多队列，即一个port配置多个接收队列或发送队列。
> 在DPDK port_init 函数中，会对发送队列个数和接收队列个数进行配置。
``` C
retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
```
> rx_rings为接收队列个数，tx_rings为发送队列个数，在这里可以直接设置每个port（网卡）的队列数量，至于网卡如何将接收到的网络包划分到多个队列，就需要对port_conf进行配置，具体的配置说明会在s实现细节的第三条（流分类）里面详细去说。
``` C
retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
```
> 这个函数是去判断port网口的队列是否支持 nb_rxd/nb_txd个接收/发送 描述符,如果不支持那么多会自动调整到边界个数(如果没有这一层，很可能出现段错误）。
``` C
for (q = 0; q < rx_rings; q++) {
    retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
            rte_eth_dev_socket_id(port), &rx_conf, mbuf_pool);
    if (retval < 0)
        return retval;
}
for (q = 0; q < tx_rings; q++) {
    retval = rte_eth_tx_queue_setup(port, q, nb_txd,
            rte_eth_dev_socket_id(port), &txconf);
    if (retval < 0)
        return retval;
}
```
> rte_eth_rx_queue_setup和rte_eth_tx_queue_setup函数设置每个队列的特性，设置描述符个数（nb_rxd和nb_txd），绑定内存池（mbuf_pool）和进行一些配置的设置（rx_conf和txconf）。

> rte_eth_dev_socket_id返回的是一个NUMA结构套接字，所谓的NUMA结构是将多台服务起连接起来当做一台使用的技术，是多CPU模式的，因为我们的服务器只有一个CPU，所以这个参数可以就这么写不管它。

2. 每个队列绑定一个核 <br/>
*ps: 参考代码：**l2fwd***
> l2fwd 详细实现了多核多port多队列情况下网络报文相邻端口的互相转发，虽然其每个port只设置了一个队列，但是队列，port以及核的绑定仍然可以参考，由于l2fwd考虑的情况比较复杂，它实现了一个分配算法，可以根据指定的命令行参数，将指定的port分配给指定的核，其中每个核可以进行多个port的消息接收处理和转发。
``` C
struct lcore_queue_conf {
	unsigned n_rx_port;
	unsigned rx_port_list[MAX_RX_QUEUE_PER_LCORE];
} __rte_cache_aligned;
struct lcore_queue_conf lcore_queue_conf[RTE_MAX_LCORE];

/* Initialize the port/queue configuration of each logical core */
RTE_ETH_FOREACH_DEV(portid) {
    /* skip ports that are not enabled */
    if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
        continue;

    /* get the lcore_id for this port */
    while (rte_lcore_is_enabled(rx_lcore_id) == 0 ||
            lcore_queue_conf[rx_lcore_id].n_rx_port ==
            l2fwd_rx_queue_per_lcore) {
        rx_lcore_id++;
        if (rx_lcore_id >= RTE_MAX_LCORE)
            rte_exit(EXIT_FAILURE, "Not enough cores\n");
    }

    if (qconf != &lcore_queue_conf[rx_lcore_id]) {
        /* Assigned a new logical core in the loop above. */
        qconf = &lcore_queue_conf[rx_lcore_id];
        nb_lcores++;
    }

    qconf->rx_port_list[qconf->n_rx_port] = portid;
    qconf->n_rx_port++;
    printf("Lcore %u: RX port %u\n", rx_lcore_id, portid);
}
```
> 这一段代码不用仔细去看，就是根据命令行参数中port和lcore的掩码以及每个核处理的队列个数（l2fwd_rx_queue_per_lcore）对core进行port的分发，最后每个核对应的port信息都存在结构体数组中（lcore_queue_conf）。

> lcore_queue_conf[lcore_id].n_rx_port 代表此lcore（逻辑核）分配到的port个数;lcore_queue_conf[lcore_id].rx_port_list 代表此lcore分配到的port id。

> 我们的DPDK-DNS负责接收的网卡只有一个，也就是只有一个port，所以不需要用这个数据结构进行存储。只需要在对应的lcore_main函数中对某一个队列中的数据进行接收和处理以及发放就可以。

> 例如如果设置了两个队列，可以0号core负责0号队列数据的接收，处理和发送（发送到0号发送队列），1号core负责1号队列数据的接收，处理和发送（发送到1号发送队列）。由于队列之间的数据完全隔离，不存在数据交互，所以不需要进行加锁。

> 在每个核的执行函数中可以通过rte_lcore_id()函数获取当前核的id，并通过这个id确定处理队列的id。从而实现队列和核的绑定。还有一点需要说明的是：
``` C
ret = 0;
/* launch per-lcore init on every lcore */
rte_eal_mp_remote_launch(l2fwd_launch_one_lcore, NULL, CALL_MASTER);
RTE_LCORE_FOREACH_SLAVE(lcore_id) {
    if (rte_eal_wait_lcore(lcore_id) < 0) {
        ret = -1;
        break;
    }
}
static int
l2fwd_launch_one_lcore(__attribute__((unused)) void *dummy)
{
	l2fwd_main_loop();
	return 0;
}
```
> l2fwd rte_eal_mp_remote_launch函数为每个核绑定执行函数l2fwd_launch_one_lcore，并通过rte_eal_wait_lcore函数等待子进程执行完成。

> l2fwd_launch_one_lcore中都会调用l2fwd_main_loop函数，l2fwd_main_loop则是每个核上运行的代码主逻辑。（此部分逻辑可以在lab3代码的基础上进行修改，理论上只需要在接收和发送时注意与队列id的对应关系）。

> 此部分代码可以直接复用，并在main_loop中实现自己的程序逻辑。
 
3. 网卡的多队列和流分类设置 <br/>
*ps: 参考：谷歌，百度，博客*
- 网卡如何将接收到数据包分散到不同的队列中，其实当前主流的网卡支持两种模式：
    1. RSS：RSS（Receive-Side Scaling，接收方扩展）
        - 根据关键字通过哈希函数计算出hash值，再由hash值确定队列。关键字针对不同的协议包会有不同的类别，例如IPV4 UDP包的关键字是由四元组组成（源IP地址、目的IP地址、源端口号、目的端口号）。不同的协议包类型对应的关键字详细参见《深入浅出DPDK》P145-P146。
        - RSS的包类型判别和hash计算，队列划分均由硬件完成，需要硬件支持。
        - 在负载均衡的应用中（我们的场景），RSS是否能将数据包均匀的散列在多个队列中，取决于真实环境中的数据包构成和hash函数的选取，有一些特殊的hash，例如对称hash可以保证Hash(src,dst) = Hash(dst,src)。
    2. Flow Director
        - Flow Director技术是Intel公司提出的根据包的字段进行精确匹配，将其分配到某个特定队列的技术。
        - Flow Director是利用网卡上存储了一张Flow Director表，表中记录了需要匹配的字段的关键字及匹配后的动作，网卡在接收到数据包后会根据关键字查这张表，然后按照表项的动作进行处理（分配队列、丢弃等等）。
        - Flow Director可以为不同包类型指定关键字以满足不同的需求，比如针对IPV4 UDP类型的包可以只匹配源端口，忽略其他字段。
    - 优缺点比较：RSS配置相对比较简单，适合用于一般场景下的负载均衡；Flow Director更强调定性，虽然配置稍微复杂，但可以实现更加精细化的功能，更容易实现出更好的效果。
- DPDK对RSS和Flow Director的配置通过查阅相关资料可知，主要是在port初始化时，对port_conf进行修改，下例实现了一个简单的RSS配置策略（由于DPDK-DNS模拟发包每次的src port几乎都不一样，所以可以使用默认的UDP关键字（源IP地址、目的IP地址、源端口号、目的端口号）进行hash。如果想实现更好的均衡策略，可以使用Flow Director只对源端口做hash，或者其他更好的优化策略，这里仅提供RSS版本的port_conf:
``` C
struct rte_eth_conf port_conf = {
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
```

# Pipeline
## 核心思路
1. 对DPDK-DNS收发包阶段进行时间上的profile，并按照时间进行阶段划分，使得每个阶段的处理时间尽可能均衡。
2. 每个处理阶段绑定一个逻辑核（lcore）进行处理。这里应当注意线程同步问题。

## 具体实现
1. 划分阶段
*ps: 参考代码：**distributor***
``` C
    dist_tx_ring = rte_ring_create("Output_ring", SCHED_TX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (dist_tx_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");

	rx_dist_ring = rte_ring_create("Input_ring", SCHED_RX_RING_SZ,
			rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
	if (rx_dist_ring == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create output ring\n");
```
> 使用rte_ring_create创建了两个无锁环形队列rx_dist_ring和dist_tx_ring，用于不同阶段线程之间的数据传输。
``` C
    uint16_t nb_ret = nb_rx;
    struct rte_ring *out_ring = p->rx_dist_ring;
    uint16_t sent = rte_ring_enqueue_burst(out_ring,
				(void *)bufs, nb_ret, NULL);
```
> rte_ring_enqueue_burst将收到的数据包进行批量入队，进入到队列rx_dist_ring中。
``` C
    const uint16_t nb_rx = rte_ring_dequeue_burst(in_r,
				(void *)bufs, BURST_SIZE, NULL);
```
> rte_ring_dequeue_burst将队列中的数据按照BURST_SIZE批量出队，实际出队数量为nb_rx。

![pipeline结构图](https://github.com/xinhaixiangyunpiao/MarkDown_Image_Repository/blob/master/3.png?raw=true)
- 这里没有进行详细的Profile，仅按照功能进行简单的划分，划分了六个线程，每个线程分配给一个lcore：
    1. 1个rx线程：
        - 从port批量接收数据，将接收到的数据包批量入队到rx_ring中。
    2. 4个处理线程：
        - 每个处理线程从rx_ring取出数据包，每个worker一次都会取n个，处理完了将结果放在tx_ring中。
    3. 1个tx线程：
        - 从tx_ring批量取出数据包，并批量发送出去。
- 线程同步：线程之间通过lcore_params传递无锁队列，利用无锁队列传递数据，具体参考代码。
- 最终的实现效果为：三个线程并行运行（接收线程，处理线程，发送线程）。
- 这里认为任务瓶颈在DPDK-DNS数据包处理，所以安排了1个接收线程，1个发送线程，4个处理线程，不同的线程数量比例可能会造成瓶颈转移，需要在实践中进行调试。

# 关于测试方式和评价标准
- 测试方式：使用pktgen在node6上进行发包，一次发送n个包，在node5运行DPDK-DNS-PARALLEL程序进行处理，多次实验后输出平均处理结果。
- 评价标准：
    1. 使用资源情况。
        - 使用了几个lcore。
    2. 最终接收包数比例。
        - 这里对发送的包数不做限制，可以根据自己的展示效果去调。最终的目标是接收尽可能多比例的包。例如在使用完8个内核的情况下发送50000个包是否可以全部接收并处理。如果使用的内核数较少，可以尽量调低发送包数。
    3. 报告和展示（重要程度依次递减）。
        - 如果两种方式都实现有加分。
        - 如果对最终结果进行瓶颈分析和最终是否受限于物理极限进行分析会有加分。
        - 报告完整度和详细程度。
        - 展示效果。
        - PPT格式和报告格式，条理清晰。
    4. 附加说明：
        - 由于RTC实现模式可能比较简单，任务量主要集中在如何调参使得接收效果更好。多队列情况时RING_SIZE，MBUF_SIZE的大小对接收包数的影响又会不同，所以尽可能设置合适的值尽可能使得中间过程的队列不会丢包。
        - Pipeline实现任务量主要集中在如何划分任务，以及各部分的同步，线程数量，负载均衡等等，最后使得流水线能够完美的跑起来。此部分代码实现可以有较高的自由度。

# 关于提交
1. 中期进度汇报
    - 截止时间：12月13日23:59
    - 内容：实验三没有完成的一定要在这个时间节点之前完成，并提交实验三的测试报告。已经完成的组别提交实验四的进展，有代码和实践进展的说进展，没实践进展的说思路或者自己的想法。
    - 格式：pdf
    - 提交方式：ftp（202.38.79.85）或邮箱（blazarx@mail.ustc.edu.cn)（优先ftp）
2. lab4最终报告
    - 截止时间：12月20日23:59
    - 内容：实验四的最终进展报告（包含实验结果截图）。
    - 格式：pdf
3. 课堂展示
    - 时间：12月23日
    - 内容：PPT，包含两部分，第一部分实验四的完成过程和完成结果，第二部分四个实验的总结收获（可能1页或2页PPT）。具体内容可能后续会在群里具体说明。

