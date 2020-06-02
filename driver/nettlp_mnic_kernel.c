#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/err.h>
#include <linux/pci.h>
#include <linux/if_ether.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip_tunnels.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/netdevice.h>
#include <linux/ipv6.h>
#include <linux/slab.h>
#include <net/checksum.h>
#include <net/ip6_checksum.h>
#include <linux/net_tstamp.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_vlan.h>
#include <linux/pci-aspm.h>
#include <linux/interrupt.h>
#include <linux/ip.h>
#include <linux/aer.h>
#include <linux/prefetch.h>
#include <linux/pm_runtime.h>
#include <linux/overflow.h>

#include "nettlp_msg.h"
#include <nettlp_mnic.h>

#define NETTLP_MNIC_VERSION "0.0.1"
#define DRV_NAME 	    "nettlp_mnic_driver"
#define MNIC_DESC_RING_LEN  1

#define wrap_ring(index,ring_size) (uint16_t)((index+1)&(ring_size-1))
#define DEFAULT_MSG_ENABLE (NETIF_MSG_DRV | NETIF_MSG_PROBE | NETIF_MSG_LINK)

static int debug = -1;

static int nettlp_mnic_init(struct net_device *ndev)
{
	pr_info("%s: start",__func__);

	ndev->tstats = netdev_alloc_pcpu_stats(struct pcpu_sw_netstats);	
	if(!ndev->tstats){
		return -ENOMEM;
	}
	
	pr_info("%s: end",__func__);

	return 0;
}

static void nettlp_mnic_uninit(struct net_device *ndev)
{
	pr_info("%s: start",__func__);

	free_percpu(ndev->tstats);

	pr_info("%s: end",__func__);
}

static void mnic_clean_tx_ring(struct mnic_ring *tx_ring)
{
	uint32_t i = tx_ring->next_to_clean;
	struct mnic_tx_buffer *tx_buffer = &tx_ring->tx_buf_info[i];


	while (i != tx_ring->next_to_use) {
		struct descriptor *eop_desc, *tx_desc;

		dev_kfree_skb_any(tx_buffer->skb);

		eop_desc = tx_buffer->next_to_watch;
		tx_desc = MNIC_TX_DESC(tx_ring, i);

		while (tx_desc != eop_desc) {
			tx_buffer++;
			tx_desc++;
			i++;
			if (unlikely(i == tx_ring->count)) {
				i=0;
				tx_buffer = tx_ring->tx_buf_info;
				tx_desc = MNIC_TX_DESC(tx_ring, 0);
			}

		}

		tx_buffer++;
		i++;
		if (unlikely(i == tx_ring->count)) {
			i = 0;
			tx_buffer = tx_ring->tx_buf_info;
		}
	}

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

}

static void mnic_clean_all_tx_rings(struct mnic_adapter *adapter)
{
	int i;
	
	for(i=0;i<adapter->num_tx_queues;i++){
		if(adapter->tx_ring[i]){
			mnic_clean_tx_ring(adapter->tx_ring[i]);
		}
	}
}


void mnic_free_tx_resource(struct mnic_ring *tx_ring)
{
	mnic_clean_tx_ring(tx_ring);
	
	vfree(tx_ring->tx_buf_info);
	tx_ring->tx_buf_info = NULL;
	
	if(tx_ring->desc){
		dma_free_coherent(tx_ring->dev,tx_ring->size,tx_ring->desc,tx_ring->dma);
		tx_ring->desc = NULL;
	}
	else{
		return;
	}
}

static void mnic_free_all_tx_resources(struct mnic_adapter *adapter)
{
	int i;
	
	for(i=0;i<adapter->num_tx_queues;i++){
		if(adapter->tx_ring[i]){
			mnic_free_tx_resource(adapter->tx_ring[i]);
		}
		else{
			pr_info("%s: no tx ring\n",__func__);
		}
	}

}
static int mnic_setup_tx_resource(struct mnic_ring *tx_ring,int i,struct mnic_adapter *adapter)
{
	int size;
	struct device *dev = tx_ring->dev;
	
	pr_info("%s: start",__func__);

	tx_ring->count = MNIC_DEFAULT_TXD;

	size = sizeof(struct mnic_tx_buffer)*tx_ring->count;
	pr_info("For buffer-> size: %d ring_count: %d",size,tx_ring->count);
	
	tx_ring->tx_buf_info = vmalloc(size);
	if(!tx_ring->tx_buf_info){
		pr_info("%s: failed to alloc tx bufffer\n",__func__);
		goto err;
	}
	pr_info("Success: allocate tx_ring->tx_buf_info");
	
	tx_ring->size = tx_ring->count*sizeof(struct descriptor);
	
	pr_info("For descriptor-> size: %lld ring_count: %d",tx_ring->size,tx_ring->count);

	tx_ring->desc = dma_alloc_coherent(dev,tx_ring->size,&tx_ring->dma,GFP_KERNEL);
	if(!tx_ring->desc){
		goto err;
	}
	pr_info("Success: allocate tx_ring->desc");

	//adapter->bar4->tx_desc_base[i] = tx_ring->dma;
	pr_info("tx descriptor base address[%d] -> %#llx\n",i,tx_ring->dma);

	tx_ring->next_to_use = 0;
	tx_ring->next_to_clean = 0;

	pr_info("%s: end",__func__);

	return 0;

err:
	vfree(tx_ring->tx_buf_info);
	tx_ring->tx_buf_info = NULL;
	return -ENOMEM;	
}


static int mnic_setup_all_tx_resources(struct mnic_adapter *adapter)
{	
	int i,ret = 0;

	pr_info("%s: start",__func__);

	for(i=0; i < adapter->num_tx_queues; i++){
		ret = mnic_setup_tx_resource(adapter->tx_ring[i],i,adapter);
		if(ret){
			pr_info("%s: failed to setup tx_resource\n",__func__);
			for(i--;i>0;i--){
				mnic_free_tx_resource(adapter->tx_ring[i]);
			}
			break;
		}
	}
	
	pr_info("%s: end",__func__);

	return ret;
}

static void mnic_clean_rx_ring(struct mnic_ring *rx_ring)
{

	dev_kfree_skb(rx_ring->skb);
	rx_ring->skb = NULL;

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

}

static void mnic_clean_all_rx_rings(struct mnic_adapter *adapter)
{
	int i;
	
	pr_info("%s: start",__func__);

	for(i=0;i<adapter->num_rx_queues;i++){
		if(adapter->rx_ring[i]){
			mnic_clean_rx_ring(adapter->rx_ring[i]);
		}
	}

	pr_info("%s: end",__func__);
}

void mnic_free_rx_resources(struct mnic_ring *rx_ring)
{
	pr_info("%s: start",__func__);

	mnic_clean_rx_ring(rx_ring);

	if (!rx_ring->desc)
		return;

	dma_free_coherent(rx_ring->dev, rx_ring->size,
			  rx_ring->desc, rx_ring->dma);

	dma_free_coherent(rx_ring->dev,2048*rx_ring->count,rx_ring->rx_buf,rx_ring->rx_dma);
	rx_ring->desc = NULL;

	pr_info("%s: end",__func__);
}

int mnic_setup_rx_resource(struct mnic_ring *rx_ring,int i,struct mnic_adapter *adapter)
{
	struct device *dev = rx_ring->dev;

	rx_ring->count = MNIC_DEFAULT_RXD;

	pr_info("%s: start",__func__);

	rx_ring->size = rx_ring->count * sizeof(struct descriptor);
	
	rx_ring->desc = dma_alloc_coherent(dev, rx_ring->size,
					   &rx_ring->dma, GFP_KERNEL);

	rx_ring->rx_buf = dma_alloc_coherent(rx_ring->dev,2048*rx_ring->count,&rx_ring->rx_dma,GFP_KERNEL);
	pr_info("For buffer-> size: %d ring_count: %d",2048*rx_ring->count,MNIC_DEFAULT_RXD);

	pr_info("For descriptor-> size: %lld ring_count: %d",rx_ring->size,rx_ring->count);
	if (!rx_ring->desc){
		goto err;
	}

	pr_info("Success: allocate rx_ring->desc");

	adapter->bar4->rx_desc_base[i] = rx_ring->dma;
	pr_info("rx desc base %d is %llx",i,rx_ring->dma);

	rx_ring->next_to_alloc = 0;
	rx_ring->next_to_clean = 0;
	rx_ring->next_to_use = 0;

	pr_info("%s: end",__func__);

	return 0;

err:
	dev_err(dev, "Unable to allocate memory for the Rx descriptor ring\n");

	return -ENOMEM;
}

static int mnic_setup_all_rx_resources(struct mnic_adapter *adapter)
{
	int i,ret=0;
	
	pr_info("%s: start",__func__);

	for(i=0;i<adapter->num_rx_queues;i++){
		ret = mnic_setup_rx_resource(adapter->rx_ring[i],i,adapter);
		if(ret){
			pr_info("%s: failed to set up rx resouce\n",__func__);
			for(i--;i>0;i--){
				mnic_free_rx_resources(adapter->rx_ring[i]);
			}
			break;
		}
	}

	pr_info("%s: end",__func__);

	return ret;
}

static irqreturn_t mnic_msix_ring(int irq,void *data)
{

	struct mnic_q_vector *q_vector = (struct mnic_q_vector *)data;
	
	napi_schedule(&q_vector->napi);

	return IRQ_HANDLED;
}

static int mnic_request_msix(struct mnic_adapter *adapter)
{
	int i,ret=0;
	int vector=0;
	int free_vector = 0;
	struct net_device *ndev = adapter->ndev;

	pr_info("%s: start \n",__func__);

	for(i=0;i<adapter->num_q_vectors;i++){
		struct mnic_q_vector *q_vector = adapter->q_vector[i];
		vector++;

		if(q_vector->rx.ring && q_vector->tx.ring){
			sprintf(q_vector->name, "%s-TxRx-%u", ndev->name,
				q_vector->rx.ring->queue_idx);
		}
		else if (q_vector->tx.ring){
			sprintf(q_vector->name, "%s-tx-%u", ndev->name,
				q_vector->tx.ring->queue_idx);
		}
		else if (q_vector->rx.ring){
			sprintf(q_vector->name, "%s-rx-%u", ndev->name,
				q_vector->rx.ring->queue_idx);
		}
		else{
			sprintf(q_vector->name, "%s-unused", ndev->name);
		}

		ret = request_irq(adapter->msix_entries[i].vector,mnic_msix_ring,0,q_vector->name,q_vector);
		if(ret){
			goto err_free;
		}
		pr_info("%s: made request_irq at %d \n",__func__,i);
	}
	

	pr_info("%s: end \n",__func__);

	return 0;

err_free:

	pr_info("%s:err_free happen",__func__);
	free_irq(adapter->msix_entries[free_vector++].vector, adapter);
	vector--;

	for (i = 0; i < vector; i++) {
		free_irq(adapter->msix_entries[free_vector++].vector,
			 adapter->q_vector[i]);
	}
	return ret;
}

static int mnic_request_irq(struct mnic_adapter *adapter)
{
	int ret;
	
	pr_info("%s: start",__func__);

	ret = mnic_request_msix(adapter);

	if(ret==0){
		pr_info("%s: end",__func__);
		goto request_done;
	}
	else{
		pr_info("%s: failed to get irq\n",__func__);
	}

request_done:
	return ret;
}

static bool mnic_clean_tx_irq(struct mnic_q_vector *q_vector,int napi_budget)
{
	struct mnic_ring *tx_ring = q_vector->tx.ring;
	struct mnic_tx_buffer *tx_buff;
	struct descriptor *tx_desc;
	uint32_t budget = q_vector->tx.work_limit;
	uint32_t i = tx_ring->next_to_clean;

	tx_buff = &tx_ring->tx_buf_info[i];
	tx_desc = MNIC_TX_DESC(tx_ring,i); 
	i -= tx_ring->count;
	
	do{
		struct descriptor *eop_desc = tx_buff->next_to_watch;
		pr_info("%s: clean tx irq",__func__);
		if(!eop_desc){
			break;
		}

		smp_rmb();
	
		tx_buff->next_to_watch = NULL;

		//dma_unmap_single(tx_ring->dev,tx_buff->dma,tx_buff->skb->len,DMA_TO_DEVICE);
		napi_consume_skb(tx_buff->skb,napi_budget);

		pr_info("dma unmap addr %#llx, dma unmap len %d",dma_unmap_addr(tx_buff,dma),dma_unmap_len(tx_buff,len));
		dma_unmap_single(tx_ring->dev,dma_unmap_addr(tx_buff,dma),dma_unmap_len(tx_buff,len),DMA_TO_DEVICE);

		tx_buff->skb = NULL;
		dma_unmap_len_set(tx_buff,len,0);
		while(tx_desc != eop_desc){
			tx_buff++;
			tx_desc++;
			i++;
			if(unlikely(!i)){
				i -= tx_ring->count;
				tx_buff = tx_ring->tx_buf_info;
				tx_desc = MNIC_TX_DESC(tx_ring,0);
			}
			if(dma_unmap_len(tx_buff,len)){
				pr_info("%s:dma unmmap len happed",__func__);
			}
		}

		tx_buff++;
		tx_desc++;
		i++;

		if(unlikely(!i)){
			i -= tx_ring->count;
			tx_buff = tx_ring->tx_buf_info;
			tx_desc = MNIC_TX_DESC(tx_ring,0);
		}

		prefetch(tx_desc);

		budget--;
	}while(likely(budget));

	i += tx_ring->count;
	tx_ring->next_to_clean = i;
	

	return true;
}


static bool mnic_is_non_eop(struct mnic_ring *rx_ring,struct descriptor *rx_desc)
{
	u32 ntc = rx_ring->next_to_clean + 1;
	
	ntc = (ntc < rx_ring->count) ? ntc : 0;
	rx_ring->next_to_clean = ntc;
	
	prefetch(MNIC_RX_DESC(rx_ring,ntc));

	return true;
}

static inline unsigned int mnic_rx_pg_order(struct mnic_ring *ring)
{
#if (PAGE_SIZE < 8192)
		return 1;
#endif
	return 0;
}


void mnic_alloc_rx_buffers(struct mnic_ring *rx_ring,uint16_t cleaned_count,struct mnic_adapter *adapter)
{
	struct descriptor *rx_desc;
	uint16_t i = rx_ring->next_to_use;
	int q_idx = rx_ring->queue_idx;
	void *rx_buf;

	
	if(!cleaned_count){
		return;
	}

	rx_desc = MNIC_RX_DESC(rx_ring,i);
	rx_buf = rx_ring->rx_buf + i;
	i -= rx_ring->count;

	do{
		rx_desc->addr = rx_ring->rx_dma;
		rx_desc->length = 2048;

		dma_map_single(rx_ring->dev,rx_desc,sizeof(rx_desc),DMA_BIDIRECTIONAL);
		dma_map_single(rx_ring->dev,rx_buf,sizeof(rx_buf),DMA_FROM_DEVICE);
		
		rx_desc++;
		rx_buf++;
		i++;
	
		if(unlikely(!i)){
			rx_desc = MNIC_RX_DESC(rx_ring,0);
			rx_buf = rx_ring->rx_buf;
			i -= rx_ring->count;
		}

		cleaned_count--;	
	}while(cleaned_count);

	i += rx_ring->count;
	
	if(i != rx_ring->next_to_use){
		rx_ring->next_to_use = i;
		rx_ring->next_to_alloc = i;
		dma_wmb();
		adapter->bar4->rx_desc_tail[q_idx] = i;
	}

}

static struct sk_buff *mnic_fetch_rx_buffer(struct mnic_ring *rx_ring,struct descriptor *rx_desc,struct sk_buff *skb)
{
	skb = netdev_alloc_skb_ip_align(rx_ring->ndev,rx_desc->length + NET_IP_ALIGN);
	if(unlikely(!skb)){
		rx_ring->rx_stats.alloc_failed++;
		return NULL;
	}

	skb_copy_to_linear_data_offset(skb,NET_IP_ALIGN,rx_ring->rx_buf,rx_desc->length);
	skb_put(skb,rx_desc->length);
	

	return skb;
}

static bool mnic_clean_rx_irq(struct mnic_q_vector *q_vector,const int budget)
{
	struct mnic_ring *rx_ring = q_vector->rx.ring;
	struct sk_buff *skb = rx_ring->skb;
	uint32_t total_bytes = 0, total_packets = 0;
	uint32_t cleaned_count = mnic_desc_unused(rx_ring);

	do{
		struct descriptor *rx_desc;

		rx_desc = MNIC_RX_DESC(rx_ring,rx_ring->next_to_clean);
		dma_rmb();
		
		dma_unmap_single(rx_ring->dev,rx_desc->addr,2048,DMA_FROM_DEVICE);

		skb = mnic_fetch_rx_buffer(rx_ring,rx_desc,skb);
		if(!skb){
			pr_err("%s: failed to fetch rx buffer\n",__func__);
			break;
		}

		cleaned_count++;
	
		mnic_is_non_eop(rx_ring,rx_desc);
		total_bytes += skb->len;
		skb_record_rx_queue(skb,rx_ring->queue_idx);

		skb->protocol = eth_type_trans(skb,rx_ring->ndev);
		skb->ip_summed = CHECKSUM_NONE;

		napi_gro_receive(&q_vector->napi,skb);

		skb = NULL;
		total_packets++;
	}while(likely(total_packets < budget));

	rx_ring->skb = skb;

	rx_ring->rx_stats.packets += total_packets;
	rx_ring->rx_stats.bytes += total_bytes;
	
	q_vector->rx.total_packets += total_packets;
	q_vector->rx.total_bytes += total_bytes;

		
	if(cleaned_count > 200){
		mnic_alloc_rx_buffers(rx_ring,cleaned_count,q_vector->adapter);
	}

	return true;
}

static int mnic_poll(struct napi_struct *napi,int budget)
{
	bool clean_complete = true;
	struct mnic_q_vector *q_vector = container_of(napi,struct mnic_q_vector,napi);

	if(q_vector->tx.ring){
		pr_info("%s:go to clean tx irq",__func__);
		clean_complete = mnic_clean_tx_irq(q_vector,budget);
	}
	if(q_vector->rx.ring){
		pr_info("%s:go to clean rx irq",__func__);
		clean_complete = mnic_clean_rx_irq(q_vector,budget);
	}

	if(clean_complete == false){
		return budget;
	}
	
	napi_complete(napi);

	return 0;
}

static void mnic_free_irq(struct mnic_adapter *adapter)
{
	int i;
	int vector = 0;

	pr_info("%s: start \n",__func__);

	for(i=0;i<adapter->num_q_vectors;i++){
		free_irq(adapter->msix_entries[vector].vector,adapter->q_vector[i]);
		vector++;
	}
	pr_info("%s: end \n",__func__);
}

static void mnic_free_all_rx_resources(struct mnic_adapter *adapter)
{
	int i;
	
	pr_info("%s: start \n",__func__);
	for(i=0;i<adapter->num_rx_queues;i++){
		if(adapter->rx_ring[i]){
			mnic_free_rx_resources(adapter->rx_ring[i]);
		}
	}
	pr_info("%s: end \n",__func__);
}

static int __mnic_open(struct net_device *ndev,bool resuming)
{
	int ret,i;
	struct mnic_adapter *adapter = netdev_priv(ndev);
	pr_info("%s: start \n",__func__);
	pr_info("%s: start allocate each value",__func__);


	ret = mnic_setup_all_tx_resources(adapter);
	if(ret){
		goto err_setup_tx;
	}
	pr_info("%s: mnic_setup_all_tx_resources done",__func__);

	ret = mnic_setup_all_rx_resources(adapter);
	if(ret){
		goto err_setup_rx;
	}
	pr_info("%s: mnic_setup_all_rx_resources done",__func__);

	for(i=0;i<adapter->num_rx_queues;i++){
		struct mnic_ring *rx_ring = adapter->rx_ring[i];
		mnic_alloc_rx_buffers(rx_ring,mnic_desc_unused(rx_ring),adapter);
	}
	pr_info("%s: mnic_alloc_rx_buffer done",__func__);

	ret = netif_set_real_num_tx_queues(adapter->ndev,adapter->num_tx_queues);
	if(ret){
		goto err_set_queues;
	}
	pr_info("%s: netif_set_real_num_tx_queues done",__func__);

	ret = netif_set_real_num_rx_queues(adapter->ndev,adapter->num_rx_queues);
	if(ret){
		goto err_set_queues;
	}
	pr_info("%s: netif_set_real_num_rx_queues done",__func__);

	netif_tx_start_all_queues(ndev);
	pr_info("%s: netif_tx_start_all_queues done",__func__);

	pr_info("%s: end \n",__func__);
	return 0;

err_set_queues:
	pr_info("%s:err_set_queues",__func__);
	mnic_free_irq(adapter);

err_setup_rx:
	pr_info("%s:err_setup_rx",__func__);
	mnic_free_all_tx_resources(adapter);

err_setup_tx:
	pr_info("%s:err_setup_tx\n",__func__);

	return ret;
}

static int mnic_open(struct net_device *ndev)
{
	return __mnic_open(ndev,false);
}

void mnic_unmap_and_free_tx_resource(struct mnic_ring *ring,
				    struct mnic_tx_buffer *tx_buffer)
{
	struct sk_buff *skb;

	pr_info("%s: start \n",__func__);

	skb = tx_buffer->skb;

	if(tx_buffer->skb){
		pr_info("%s: dma_unmap_single the mapped area",__func__);
		//dma_unmap_single(ring->dev,tx_buffer->dma,skb->len,DMA_TO_DEVICE);
		dma_unmap_single(ring->dev,dma_unmap_addr(tx_buffer,dma),dma_unmap_len(tx_buffer,len),DMA_TO_DEVICE);
		pr_info("%s: free skb",__func__);
		dev_kfree_skb_any(skb);
	}
	else{
		pr_info("%s: dma_unmap_single the mapped area",__func__);
		//dma_unmap_single(ring->dev,tx_buffer->dma,skb->len,DMA_TO_DEVICE);
		dma_unmap_single(ring->dev,dma_unmap_addr(tx_buffer,dma),dma_unmap_len(tx_buffer,len),DMA_TO_DEVICE);
	}

	tx_buffer->next_to_watch = NULL;
	tx_buffer->skb = NULL;
	dma_unmap_len_set(tx_buffer, len, 0);

	pr_info("%s: end \n",__func__);
}

static int __mnic_maybe_stop_tx(struct mnic_ring *tx_ring,uint16_t size)
{
	struct net_device *ndev = tx_ring->ndev;
	
	pr_info("%s: start \n",__func__);

	netif_stop_subqueue(ndev,tx_ring->queue_idx);

	smp_mb();
	
	if(mnic_desc_unused(tx_ring) < size){
		return -EBUSY;
	}

	netif_wake_subqueue(ndev,tx_ring->queue_idx);

	u64_stats_update_begin(&tx_ring->tx_syncp2);
	tx_ring->tx_stats.restart_queue2++;
	u64_stats_update_end(&tx_ring->tx_syncp2);

	pr_info("%s: end \n",__func__);
	return 0;
}

static inline int mnic_maybe_stop_tx(struct mnic_ring *ring,const uint16_t size)
{
	if(mnic_desc_unused(ring) >= size){
		return 0;
	}
	
	return __mnic_maybe_stop_tx(ring,size);

}

static int mnic_tx_map(struct mnic_ring *tx_ring,struct mnic_tx_buffer *first,const uint8_t hdr_len,struct mnic_adapter *adapter)
{
	uint8_t t,num = 0;
	struct sk_buff *skb = first->skb;
	struct mnic_tx_buffer *tx_buff = NULL;
	struct descriptor *tx_desc,*tx_desc_prev;
	skb_frag_t *frag;
	dma_addr_t dma;
	uint16_t i = tx_ring->next_to_use;
	int q_idx = tx_ring->queue_idx;
	uint32_t pktlen = skb->len;
	unsigned int size,data_len;

	t = i;
	tx_desc_prev = MNIC_TX_DESC(tx_ring,i);
	tx_desc = MNIC_TX_DESC(tx_ring,i);

	size = skb_headlen(skb);
	data_len = skb->data_len;

	dma = dma_map_single(tx_ring->dev,skb->data,size,DMA_TO_DEVICE);
	tx_buff = first;
	
	/*
	dma_unmap_len_set(tx_buff,len,size);
	dma_unmap_addr_set(tx_buff,dma,dma);

	tx_desc->addr = dma;
	tx_desc->length = pktlen;
	*/

	pr_info("%s:dma addr is %#llx, skb_headlen %d \n",__func__,dma,size);

	if(dma_mapping_error(tx_ring->dev,dma)){
		goto dma_error;
	}

	for(frag = &skb_shinfo(skb)->frags[0];;frag++){
		if(dma_mapping_error(tx_ring->dev,dma)){
			goto dma_error;
		}
		
		dma_unmap_len_set(tx_buff,len,size);
		dma_unmap_addr_set(tx_buff,dma,dma);
	
		tx_desc->addr = dma;
		tx_desc->length = pktlen;
		
		while(unlikely(size > MNIC_MAX_DATA_PER_TXD)){
			i++;
			tx_desc++;
	
			if(i == tx_ring->count){
				tx_desc = MNIC_TX_DESC(tx_ring,0);
				i = 0;
			}
			
			dma += MNIC_MAX_DATA_PER_TXD;
			size -= MNIC_MAX_DATA_PER_TXD;

			tx_desc->addr = cpu_to_le64(dma);
			tx_desc->length = skb->len;
		}
	
		if(likely(!data_len)){
			break;
		}

		i++;
		tx_desc++;
		if(i == tx_ring->count){
			tx_desc = MNIC_TX_DESC(tx_ring,0);
			i = 0;
		}
		
		pr_info("%s: scatter gather \n",__func__);

		size = skb_frag_size(frag);
		data_len -= size;
		pr_info("%s: data len is %d\n",__func__,data_len);
		
		dma = skb_frag_dma_map(tx_ring->dev,frag,0,size,DMA_TO_DEVICE);
		tx_buff = &tx_ring->tx_buf_info[i];
	}

	dma_wmb();

	first->next_to_watch = tx_desc;

	i++;
	if(tx_ring->count == i){
		i=0;
	}
	tx_ring->next_to_use = i;

	while(t!=i){
		adapter->bar4->tx_pkt_addr[q_idx] = tx_desc_prev->addr;
		adapter->bar4->tx_pkt_len[q_idx] = tx_desc_prev->length;
		tx_desc_prev++;
		t++;
		if(t == tx_ring->count){
			tx_desc_prev = MNIC_TX_DESC(tx_ring,0);
			t = 0;
		}
	}

	adapter->ndev->stats.tx_packets++;
	adapter->ndev->stats.tx_bytes += pktlen;

	return 0;

dma_error:
	dev_err(tx_ring->dev, "TX DMA map failed\n");

	for (;;) {
		pr_info("%s: for dma_unmpa failed",__func__);
		tx_buff = &tx_ring->tx_buf_info[i];
		mnic_unmap_and_free_tx_resource(tx_ring, tx_buff);
		if (tx_buff == first)
			break;
		if (i == 0)
			i = tx_ring->count;
		i--;
	}

	tx_ring->next_to_use = i;
	return -1;
}

static void mnic_irq_disable(struct mnic_adapter *adapter);

void mnic_down(struct mnic_adapter *adapter)
{
	struct net_device *ndev = adapter->ndev;
	
	pr_info("%s: start\n",__func__);

	netif_carrier_off(ndev);
	netif_tx_stop_all_queues(ndev);

	mnic_irq_disable(adapter);

	mnic_clean_all_tx_rings(adapter);
	mnic_clean_all_rx_rings(adapter);
	
}

static int __mnic_close(struct net_device *ndev,bool suspending)
{
	struct mnic_adapter *adapter = netdev_priv(ndev);
	struct pci_dev *pdev = adapter->pdev;

	pr_info("%s: start\n",__func__);

	if(!suspending){
		pm_runtime_get_sync(&pdev->dev);
	}

	mnic_down(adapter);

	mnic_free_all_tx_resources(adapter);
	mnic_free_all_rx_resources(adapter);
		
	if(!suspending){
		pm_runtime_put_sync(&pdev->dev);
	}

	pr_info("%s: end\n",__func__);

	return 0;
}

int mnic_close(struct net_device *ndev)
{
	pr_info("%s: start \n",__func__);

	if(netif_device_present(ndev) || ndev->dismantle){
		return __mnic_close(ndev,false);
	}

	pr_info("%s: start \n",__func__);

	return 0;
}

static netdev_tx_t mnic_xmit_frame_ring(struct sk_buff *skb,struct mnic_ring *tx_ring,struct mnic_adapter *adapter)
{
	struct mnic_tx_buffer *tx_buff;
	uint8_t hdr_len = 0;

	tx_buff = &tx_ring->tx_buf_info[tx_ring->next_to_use];
	tx_buff->skb = skb;
	tx_buff->bytecount = skb->len;	
	
	mnic_tx_map(tx_ring,tx_buff,hdr_len,adapter);

	return NETDEV_TX_OK;
}

static inline struct mnic_ring *mnic_tx_queue_mapping(struct mnic_adapter *adapter,struct sk_buff *skb)
{
	uint32_t r_idx = skb->queue_mapping;
	
	if(r_idx >= adapter->num_tx_queues){
		r_idx = r_idx % adapter->num_tx_queues;
	}

	pr_info("%s: queue mapping is %d\n",__func__,r_idx);

	return adapter->tx_ring[r_idx];
}

static netdev_tx_t mnic_xmit_frame(struct sk_buff *skb,struct net_device *netdev)
{
	struct mnic_adapter *adapter = netdev_priv(netdev);
	
	if(skb_put_padto(skb,17)){
		return NETDEV_TX_OK;
	}

	return mnic_xmit_frame_ring(skb,mnic_tx_queue_mapping(adapter,skb),adapter);
}

static int nettlp_mnic_set_mac(struct net_device *ndev,void *p)
{
	struct mnic_adapter *adapter = netdev_priv(ndev);	
	struct sockaddr *addr = p;

	pr_info("%s: start \n",__func__);

	if(!is_valid_ether_addr(addr->sa_data)){
		return -EADDRNOTAVAIL;
	}

	memcpy(ndev->dev_addr,addr->sa_data,ndev->addr_len);
	mnic_get_mac(adapter->bar0->srcmac,ndev->dev_addr);

	pr_info("%s: end \n",__func__);

	return 0;
}

static const struct net_device_ops nettlp_mnic_ops = {
	.ndo_init		= nettlp_mnic_init,
	.ndo_uninit		= nettlp_mnic_uninit,
	.ndo_open		= mnic_open, 
	.ndo_stop		= mnic_close,
	.ndo_start_xmit 	= mnic_xmit_frame,
	.ndo_get_stats64  	= ip_tunnel_get_stats64,
	.ndo_change_mtu 	= eth_change_mtu,
	.ndo_validate_addr 	= eth_validate_addr,
	.ndo_set_mac_address	= nettlp_mnic_set_mac,
};

static void mnic_reset_q_vector(struct mnic_adapter *adapter, int v_idx)
{
	struct mnic_q_vector *q_vector = adapter->q_vector[v_idx];

	pr_info("%s: start \n",__func__);

	if(!q_vector){
		return;
	}

	if (q_vector->tx.ring){
		adapter->tx_ring[q_vector->tx.ring->queue_idx] = NULL;
	}

	if (q_vector->rx.ring){
		adapter->tx_ring[q_vector->rx.ring->queue_idx] = NULL;
	}

	netif_napi_del(&q_vector->napi);
	pr_info("%s: end \n",__func__);
}

static void mnic_reset_interrupt_capability(struct mnic_adapter *adapter)
{

	int v_idx = adapter->num_q_vectors;

	pr_info("%s: start \n",__func__);

	pci_disable_msix(adapter->pdev);
	while(v_idx--){
		mnic_reset_q_vector(adapter,v_idx);
	}
	pr_info("%s: end \n",__func__);
}

static void mnic_free_q_vector(struct mnic_adapter *adapter, int v_idx)
{
	struct mnic_q_vector *q_vector = adapter->q_vector[v_idx];

	pr_info("%s: start \n",__func__);

	adapter->q_vector[v_idx] = NULL;
	if(q_vector){
		kfree_rcu(q_vector, rcu);
	}
	pr_info("%s: end \n",__func__);
}

static void mnic_free_q_vectors(struct mnic_adapter *adapter)
{
	int v_idx = adapter->num_q_vectors;

	pr_info("%s: start \n",__func__);
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;	

	adapter->num_q_vectors = 0;

	while (v_idx--){
		mnic_free_q_vector(adapter, v_idx);
	}

	pr_info("%s: end \n",__func__);
}
static void mnic_clear_interrupt_scheme(struct mnic_adapter *adapter)
{
	pr_info("%s: start \n",__func__);
	mnic_free_q_vectors(adapter);
	mnic_reset_interrupt_capability(adapter);
	pr_info("%s: end \n",__func__);
}

static void mnic_set_interrupt_capability(struct mnic_adapter *adapter,bool msix)
{
	int ret;
	int numvecs,i;

	pr_info("%s: start \n",__func__);
	if(adapter->rss_queues > MAX_MSIX_ENTRIES){
		pr_info("%s: adpter->rss_queus over MAX MSIX ENTRIES",__func__);
	}

	adapter->num_rx_queues = adapter->rss_queues;
	adapter->num_tx_queues = adapter->rss_queues;

	numvecs = adapter->num_rx_queues;
	numvecs += adapter->num_tx_queues;

	adapter->num_q_vectors = numvecs;

	for(i=0;i<numvecs;i++){
		adapter->msix_entries[i].entry = i;	
	}
	
	ret = pci_enable_msix_range(adapter->pdev,adapter->msix_entries,numvecs,numvecs);

	if(ret > 0){
		pr_info("enabled %d msix",ret);
		return;
	}

	mnic_reset_interrupt_capability(adapter);

	pr_info("%s: end \n",__func__);
}


static void mnic_add_ring(struct mnic_ring *ring,struct mnic_ring_container *head)
{
	head->ring = ring;
	head->count++;
}

static int mnic_alloc_q_vector(struct mnic_adapter *adapter,int v_count,int v_idx,int txr_count,int txr_idx,int rxr_count,int rxr_idx)
{
	struct mnic_q_vector *q_vector;
	struct mnic_ring *ring;
	int ring_count,size;
	
	pr_info("%s: start \n",__func__);

	if(txr_count > 1 || rxr_count > 1){
		return -ENOMEM;
	}

	ring_count = txr_count + rxr_count;
	size = sizeof(struct mnic_q_vector)+(sizeof(struct mnic_ring)*ring_count);
	
	q_vector = kzalloc(size, GFP_KERNEL);
	if(!q_vector){
		return -ENOMEM;
	}

	netif_napi_add(adapter->ndev,&q_vector->napi,mnic_poll,MNIC_NAPI_WEIGHT);

	adapter->q_vector[v_idx] = q_vector;
	q_vector->adapter = adapter;

	q_vector->tx.work_limit = adapter->tx_work_limit;

	ring = q_vector->ring;
	
	if (rxr_count) {
		if (!adapter->rx_itr_setting || adapter->rx_itr_setting > 3)
			q_vector->itr_val = adapter->rx_itr_setting;
	} 
	else {
		if (!adapter->tx_itr_setting || adapter->tx_itr_setting > 3)
			q_vector->itr_val = adapter->tx_itr_setting;
	}
	
	if (txr_count) {
		ring->dev = &adapter->pdev->dev;
		ring->ndev = adapter->ndev;

		ring->q_vector = q_vector;

		mnic_add_ring(ring, &q_vector->tx);

		ring->count = adapter->tx_ring_count;
		ring->queue_idx = txr_idx;

		adapter->tx_ring[txr_idx] = ring;

		ring++;
	}

	if(rxr_count){
		ring->dev = &adapter->pdev->dev;
		ring->ndev = adapter->ndev;

		ring->q_vector = q_vector;
		mnic_add_ring(ring,&q_vector->rx);
	
		ring->count = adapter->rx_ring_count;
		ring->queue_idx = rxr_idx;
	
		adapter->rx_ring[rxr_idx] = ring;
	}

	pr_info("%s: end \n",__func__);

	return 0;
}

static int mnic_alloc_q_vectors(struct mnic_adapter *adapter)
{
	int q_vectors = adapter->num_q_vectors;
	int rxr_remaining = adapter->num_rx_queues;
	int txr_remaining = adapter->num_tx_queues;
	int rxr_idx = 0, txr_idx = 0, v_idx = 0;
	int ret;
	
	pr_info("%s: start \n",__func__);

	if(q_vectors >= (rxr_remaining + txr_remaining)){
		for(;rxr_remaining;v_idx++){
			ret = mnic_alloc_q_vector(adapter,q_vectors,v_idx,0,0,1,rxr_idx);
			if(ret){
				goto err_out;
			}
			rxr_remaining--;
			rxr_idx++;
			pr_info("%s: allocate q_vector for rx at %d \n",__func__,rxr_idx);
		}
	}

	for(;v_idx < q_vectors;v_idx++){
		int rqpv = DIV_ROUND_UP(rxr_remaining,q_vectors - v_idx);
		int tqpv = DIV_ROUND_UP(txr_remaining,q_vectors - v_idx);

		pr_info("tqpv: %d , rqpv: %d\n",tqpv,rqpv);
		ret = mnic_alloc_q_vector(adapter,q_vectors,v_idx,tqpv,txr_idx,rqpv,rxr_idx);
		if(ret){
			goto err_out;
		}
		
		rxr_remaining -= rqpv;
		txr_remaining -= tqpv;
		rxr_idx++;	
		txr_idx++;
		pr_info("%s: allocate q_vector for tx at %d \n",__func__,txr_idx);
	}

	pr_info("%s: end \n",__func__);
	return 0;

err_out:
	adapter->num_tx_queues = 0;
	adapter->num_rx_queues = 0;
	adapter->num_q_vectors = 0;

	while (v_idx--){
		mnic_free_q_vector(adapter, v_idx);
	}

	return -ENOMEM;
}

static int mnic_init_interrupt_scheme(struct mnic_adapter *adapter,bool msix)
{
	int ret;
	
	pr_info("%s: start \n",__func__);

	mnic_set_interrupt_capability(adapter,msix);
	
	ret = mnic_alloc_q_vectors(adapter);
	if(ret){
		pr_info("Unable to allocate memory for vectors\n");
		goto err_alloc_q_vectors;
	}

	pr_info("%s: end \n",__func__);

	return 0;

err_alloc_q_vectors:
	mnic_reset_interrupt_capability(adapter);
	return ret;
}

static void mnic_irq_disable(struct mnic_adapter *adapter)
{
	int i;
	pr_info("%s: start \n",__func__);
	for(i=0;i < adapter->num_q_vectors;i++){
		synchronize_irq(adapter->msix_entries[i].vector);
	}	
	pr_info("%s: end \n",__func__);
}

static int mnic_sw_init(struct mnic_adapter *adapter)
{
	uint32_t max_rss_queues;
	struct net_device *ndev = adapter->ndev;

	pr_info("%s: start \n",__func__);

	adapter->tx_ring_count = MNIC_DEFAULT_TXD;
	adapter->rx_ring_count = MNIC_DEFAULT_RXD;

	adapter->tx_itr_setting = MNIC_DEFAULT_ITR;
	adapter->rx_itr_setting = MNIC_DEFAULT_ITR;

	adapter->tx_work_limit = MNIC_DEFAULT_TX_WORK;

	adapter->max_frame_size = ndev->mtu + ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN;
	adapter->min_frame_size  = ETH_ZLEN + ETH_FCS_LEN;


	max_rss_queues = MNIC_MAX_RX_QUEUES;
	adapter->rss_queues = min_t(uint32_t,max_rss_queues,num_online_cpus());

	if(mnic_init_interrupt_scheme(adapter,true)){
		pr_info("%s: Unable to allocate memory for queues \n",__func__);
		return -ENOMEM;
	}

	pr_info("%s: end \n",__func__);

	return 0;
}

static int mnic_probe(struct pci_dev *pdev,const struct pci_device_id *ent)
{
	int i,ret;
	void *bar0,*bar2,*bar4;
	uint64_t bar0_start,bar0_len;
	uint64_t bar2_start,bar2_len;
	uint64_t bar4_start,bar4_len;
	struct net_device *ndev;
	struct mnic_adapter *adapter;

	pr_info("%s: start \n",__func__);
	pr_info("%s: register nettlp modern nic device %s\n",
					__func__,pci_name(pdev));

	ret = pci_enable_device(pdev);
	if(ret){
		goto err1;
	}	

	ret = pci_request_regions(pdev,DRV_NAME);
	if(ret){
		goto err2;
	}

	pci_set_master(pdev);
	pci_save_state(pdev);

	bar0_start = pci_resource_start(pdev,0);
	bar0_len = pci_resource_len(pdev,0);
	bar0 = ioremap(bar0_start,bar0_len);
	if(!bar0){
		pr_err("failed to ioremap BAR0 %llx\n",bar0_start);
		goto err3;
	}		
	pr_info("BAR0 %llx is mapped to %p\n",bar0_start,bar0);

	bar2_start = pci_resource_start(pdev,2);
	bar2_len = pci_resource_len(pdev,2);
	bar2 = ioremap(bar2_start,bar2_len);
	if(!bar2){
		pr_err("failed to ioremap BAR2 %llx\n",bar2_start);
		goto err4;
	}		
	pr_info("BAR2 %llx is mapped to %p\n",bar2_start,bar2);

	bar4_start = pci_resource_start(pdev,4);
	bar4_len = pci_resource_len(pdev,4);
	bar4 = ioremap(bar4_start,bar4_len);
	if(!bar4){
		pr_err("failed to ioremap BAR4 %llx\n",bar4_start);
		goto err5;
	}		
	pr_info("BAR4 %llx is mapped to %p\n",bar4_start,bar4);

	ret = -ENOMEM;

	ndev = alloc_etherdev_mq(sizeof(struct mnic_adapter),MNIC_MAX_TX_QUEUES);
	if(!ndev){
		goto err6;
	}

	SET_NETDEV_DEV(ndev,&pdev->dev);
	pci_set_drvdata(pdev,ndev);

	adapter = netdev_priv(ndev);
	adapter->ndev = ndev;
	adapter->pdev = pdev;
	adapter->msg_enable = netif_msg_init(debug,DEFAULT_MSG_ENABLE);
	adapter->bar0 = bar0;
	adapter->bar2 = bar2;	
	adapter->bar4 = bar4;
	adapter->bar4_start = bar4_start;

	mnic_get_mac(ndev->dev_addr,adapter->bar0->srcmac);	
	if(!is_valid_ether_addr(ndev->dev_addr)){
		dev_err(&pdev->dev,"Invalid Mac Address\n");
		ret = -EIO;
		return -ENOMEM;
	}

	ndev->needs_free_netdev = true;
	ndev->netdev_ops = &nettlp_mnic_ops;
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = ETH_MAX_MTU;
	ndev->features = NETIF_F_SG;

	ret = mnic_sw_init(adapter);
	if(ret){
		goto err9;		
	}

	strcpy(ndev->name,"mnic");
	ret = register_netdev(ndev);
	if(ret){
		goto err10;
	}
	
	ret = mnic_request_irq(adapter);
	if(ret){
		goto err10;
	}
	pr_info("%s: mnic_request_irq done",__func__);

	for(i=0;i<adapter->num_q_vectors;i++){
		napi_enable(&(adapter->q_vector[i]->napi));			
	}
	pr_info("%s: napi_enable done",__func__);

	nettlp_msg_init(adapter->bar4_start,PCI_DEVID(adapter->pdev->bus->number,adapter->pdev->devfn),adapter->bar2);

	pr_info("%s: probe finished.",__func__);
	
	return 0;

err10:
	pr_info("%s:err_req_irq",__func__);
err9:
	mnic_clear_interrupt_scheme(adapter);
err6:
	iounmap(bar4);
err5:
	iounmap(bar2);
err4:
	iounmap(bar0);
err3:
	pci_release_regions(pdev);
err2:
	pci_disable_device(pdev);
err1:

	return ret;
}


static void mnic_remove(struct pci_dev *pdev)
{
	int i;
	struct net_device *dev = pci_get_drvdata(pdev);
	struct mnic_adapter *adapter = netdev_priv(dev);

	pr_info("start remove pci config");

	nettlp_msg_fini();

	for(i=0;i<adapter->num_q_vectors;i++){
		synchronize_irq(adapter->msix_entries[i].vector);
	}

	for(i=0;i<adapter->num_q_vectors;i++){
		if(adapter->q_vector[i]){
			napi_synchronize(&adapter->q_vector[i]->napi);
			napi_disable(&adapter->q_vector[i]->napi);
		}
	}

	mnic_free_irq(adapter);

	unregister_netdev(dev);

	mnic_clear_interrupt_scheme(adapter);

	iounmap(adapter->bar4);
	iounmap(adapter->bar2);
	iounmap(adapter->bar0);

	pci_release_regions(pdev);
	pci_disable_device(pdev);

	return;
}

static const struct pci_device_id mnic_pci_tbl[] = {
	{0x3776,0x8022,PCI_ANY_ID,PCI_ANY_ID,0,0,0},
	{0,}
};
MODULE_DEVICE_TABLE(pci,mnic_pci_tbl);

struct pci_driver nettlp_mnic_pci_driver = {
	.name 		= DRV_NAME,
	.id_table	= mnic_pci_tbl,
	.probe		= mnic_probe,
	.remove		= mnic_remove,	
};

static int __init nettlp_mnic_module_init(void)
{
	pr_info("nettlp_mnic is loaded\n");

	return pci_register_driver(&nettlp_mnic_pci_driver);
}
module_init(nettlp_mnic_module_init);

static void __exit nettlp_mnic_module_exit(void)
{
	pci_unregister_driver(&nettlp_mnic_pci_driver);

	pr_info("nettlp_mnic is unloaded\n");

	return;
}
module_exit(nettlp_mnic_module_exit);

MODULE_AUTHOR("Ryusei Shiiba <siiba@sfc.wide.ad.jp>");
MODULE_DESCRIPTION("nettlp_mnic_kernel");
MODULE_LICENSE("GPL");
MODULE_VERSION(NETTLP_MNIC_VERSION);
