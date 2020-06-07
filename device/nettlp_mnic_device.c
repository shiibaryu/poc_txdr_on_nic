#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/uio.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <signal.h>
#include <poll.h>
#include <pthread.h>

#include <libtlp.h>
#include "nettlp_mnic_device.h"

//struct nettlp *rx_dma_nt[5];
struct nettlp_mnic *mnic_f;
void mnic_free(struct nettlp_mnic *mnic);

int tap_alloc(char *dev)
{
        struct ifreq ifr;

        memset(&ifr,0,sizeof(ifr));
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
        strncpy(ifr.ifr_name,dev,IFNAMSIZ);

        int fd = open("/dev/net/tun",O_RDWR);
        if(fd < 0){
                perror("open");
                return -1;
        }

        if(ioctl(fd,TUNSETIFF,(void *)&ifr)<0){
                perror("ioctl");
                close(fd);
                return -1;
        }

        return fd;
}

int tap_up(char *dev)
{
	size_t len;
        struct ifreq ifr;
	socklen_t i = sizeof(len);

        int fd = socket(AF_INET,SOCK_DGRAM,0);
        if(fd < 0){
                perror("socket");
                return -1;
        }

	/*set an option for a cpu affinity of socket*/
	if(setsockopt(fd,SOL_SOCKET,SO_INCOMING_CPU,&len,i)<0){
		perror("setsockopt");
	}

        memset(&ifr,0,sizeof(ifr));
        ifr.ifr_flags = IFF_UP;
        strncpy(ifr.ifr_name,dev,IFNAMSIZ);

        if(ioctl(fd,SIOCSIFFLAGS,(void *)&ifr) < 0){
                perror("ioctl");
                return -1;
        }
        close(fd);
        return 0;
}

static int caught_signal = 0;

void signal_handler(int signal)
{
	caught_signal = 1;
	mnic_free(mnic_f);
	nettlp_stop_cb();
}

static void poll_txd_tail_idx(struct tx_desc_ctl *txd_ctl)
{
	while(txd_ctl->tail == txd_ctl->head){}
}

void *mnic_tx(void *arg)
{
	int ret,num;
	struct tx_ctl *txc = (struct tx_ctl *)arg;
	int offset = txc->offset;
	struct nettlp_mnic *mnic = txc->mnic;
	struct descriptor *tx_desc = mnic->tx_desc[offset];
	struct tx_desc_ctl *txd_ctl = mnic->tx_desc_ctl + offset;
	unsigned char *buf = txd_ctl->tx_buf;
	struct nettlp_msix *tx_irq = mnic->tx_irq + offset;

	while(1){

		poll_txd_tail_idx(txd_ctl);

		num = txd_ctl->tail - txd_ctl->head;
		if(num < 0){
			num += DESC_ENTRY_SIZE;
		}

		while(num){
			info("tx tail idx %d, tx head idx %d",txd_ctl->tail, txd_ctl->head);
			info("tx descriptor: packet address is %#lx, packet length is %lu",tx_desc->addr,tx_desc->length);
			info("offset is %d",offset);

			//1. dma read a packet
			info("dma_read a packet");
			ret = dma_read_aligned(&mnic->tx_nt[offset],tx_desc->addr,buf,tx_desc->length,MRRS);
			if(ret < tx_desc->length){
				debug("failed to read tx pkt from %#lx, %lu-byte",tx_desc->addr,tx_desc->length);
				buf = NULL;
			}

			if(buf == NULL){
				info("buf is null");
				goto tx_done;
			}

			//2. transmit a packet
			info("transmit a packet");
			ret = write(mnic->tap_fd,buf,tx_desc->length);
			if(ret < tx_desc->length){
				fprintf(stderr,"failed to read tx pkt from %lx,%lu-bytes\n",tx_desc->addr,tx_desc->length);
				perror("write");
			}
tx_done:
			num--;
			buf++;
			tx_desc++;
			txd_ctl->head++;
			if(txd_ctl->head > DESC_ENTRY_SIZE - 1){
				txd_ctl->head = 0;
				tx_desc = mnic->tx_desc[offset];
				buf = (mnic->tx_desc_ctl + offset)->tx_buf;
			}
		}

		//3. generate a tx interrupt
		//info("generate a tx interrupt");
		ret = dma_write(&mnic->tx_nt[offset],tx_irq->addr,&tx_irq->data,sizeof(tx_irq->data));
		if(ret < 0){
			fprintf(stderr,"failed to send tx interrupt\n");
			perror("dma_write");
		}
	}
}

void mnic_rx(uint32_t idx,struct nettlp *nt,struct nettlp_mnic *mnic,unsigned int offset)
{
	int ret;
	struct descriptor *rx_desc = mnic->rx_desc[offset];
	uintptr_t *rx_desc_base = mnic->rx_desc_base + offset;
	struct rx_desc_ctl *rxd_ctl = mnic->rx_desc_ctl + offset;

	if(*rx_desc_base == 0){
		fprintf(stderr,"rx_desc base is 0\n");
		return;
	}

	rx_desc += rxd_ctl->tail;
	
	while(rxd_ctl->tail != idx){
		ret = dma_read(&mnic->rx_nt[offset],rxd_ctl->desc_tail,rx_desc,sizeof(struct descriptor));
		if(ret < sizeof(struct descriptor)){
			fprintf(stderr,"failed to read rx desc from %#lx\n",rxd_ctl->desc_tail);
			return;
		}

		rx_desc++;
		rxd_ctl->tail++;
		rxd_ctl->desc_tail += sizeof(struct descriptor);

		if(rxd_ctl->tail > DESC_ENTRY_SIZE-1){	
			rx_desc = mnic->rx_desc[offset];
			rxd_ctl->tail = 0;
			rxd_ctl->desc_tail = *rx_desc_base;
		}
	}

	mnic->rx_state[offset] = RX_STATE_READY;
}

static inline unsigned int get_bar4_rxt_offset(uintptr_t start,uintptr_t received)
{
	return (received - start - RX_BASE_SUM)/8;
}

static inline unsigned int get_bar4_tx_pkt_addr_offset(uintptr_t start,uintptr_t received)
{
	unsigned int offset;
	offset =  (received - start - (BAR4_TX_PKT_ADDR))/16;
	return offset;
}

static inline unsigned int get_bar4_tx_pkt_len_offset(uintptr_t start,uintptr_t received)
{
	unsigned int offset;
	offset =  (received - start - (BAR4_TX_PKT_LEN))/16;
	return offset;
}

int nettlp_mnic_mwr(struct nettlp *nt,struct tlp_mr_hdr *mh,void *data,size_t count,void *arg)
{
	uint32_t *rd;
	uint64_t *d;
	unsigned int offset;
	struct nettlp_mnic *mnic = arg;
	uintptr_t dma_addr;

	dma_addr = tlp_mr_addr(mh);
	//info("dma addr is %#lx, base addr is %#lx",dma_addr,mnic->bar4_start);
	
	if(is_mwr_addr_rx_desc_base(mnic->bar4_start,dma_addr)){
		uintptr_t *rxd_base = mnic->rx_desc_base + mnic->rx_queue_id;
		struct rx_desc_ctl *rxd_ctl = mnic->rx_desc_ctl + mnic->rx_queue_id;
		*rxd_base = *((uintptr_t *)data);
		rxd_ctl->desc_head = *rxd_base;
		rxd_ctl->desc_tail = *rxd_base;
		info("Queue %d: RX desc base is %lx, queue id is %d",mnic->rx_queue_id,*rxd_base,mnic->rx_queue_id);
		mnic->rx_queue_id++;
	}
	else if(is_mwr_addr_rx_desc_ptr(mnic->bar4_start,dma_addr)){
		rd = (uint32_t *)data;
		offset = get_bar4_rxt_offset(mnic->bar4_start,dma_addr);
		mnic_rx(*rd,nt,mnic,offset);
	}
	else if(is_mwr_addr_tx_pkt_addr(mnic->bar4_start,dma_addr)){
		struct descriptor *tx_desc;

		d = (uint64_t *)data;
		offset = get_bar4_tx_pkt_addr_offset(mnic->bar4_start,dma_addr);
		tx_desc = mnic->tx_desc[offset] + (mnic->tx_desc_ctl + offset)->tail;
		tx_desc->addr = *d;
	}
	else if(is_mwr_addr_tx_pkt_len(mnic->bar4_start,dma_addr)){
		struct descriptor *tx_desc;

		d = (uint64_t *)data;
		offset = get_bar4_tx_pkt_len_offset(mnic->bar4_start,dma_addr);
		tx_desc = mnic->tx_desc[offset] + (mnic->tx_desc_ctl + offset)->tail;
		tx_desc->length = *d;
		
		if((mnic->tx_desc_ctl + offset)->tail != DESC_ENTRY_SIZE - 1){
			(mnic->tx_desc_ctl + offset)->tail++;
		}
		else{
			(mnic->tx_desc_ctl + offset)->tail = 0;
		}
	}
	else{
		debug("else");
	}

	return 0;
}

/*actual rx part*/
void *nettlp_mnic_tap_read_thread(void *arg)
{
	int ret,pktlen;
	struct tap_rx_ctl *tap_rx_ctl = arg;
	char buf[4096];
	uintptr_t rxd_addr;
	uintptr_t *rx_desc_base = tap_rx_ctl->rx_desc_base;
	int tap_fd = tap_rx_ctl->tap_fd;
	int *rx_state = tap_rx_ctl->rx_state;
	struct descriptor *rx_desc = tap_rx_ctl->rx_desc;
	struct nettlp_msix *rx_irq = tap_rx_ctl->rx_irq;
	struct rx_desc_ctl *rxd_ctl = tap_rx_ctl->rxd_ctl;
	struct nettlp *rx_nt = tap_rx_ctl->rx_nt;
	struct pollfd x[1] = {{.fd = tap_rx_ctl->tap_fd, .events = POLLIN}};

	while(1){
		if(caught_signal){
			break;
		}
		
		ret = poll(x,1,500);

		if(ret < 0 || ret == 0 || !(x[0].revents & POLLIN)){
			continue;
		}

		pktlen = read(tap_fd,buf,sizeof(buf));
		if(pktlen < 0){
			perror("read");
			continue;
		}

		if(*rx_state != RX_STATE_READY){
			info("rx_state is not ready");
			continue;
		}
		
		*rx_state = RX_STATE_BUSY;
		rxd_addr = rxd_ctl->desc_head;
		
		ret = dma_write_aligned(rx_nt,rx_desc->addr,buf,pktlen,MPS);
		if(ret < 0){
			debug("buf to rx_desc: failed to dma_write to %lx",rx_desc->addr);
			continue;
		}
	
		rx_desc->length = pktlen;
		ret = dma_write(rx_nt,rxd_addr,rx_desc,sizeof(rx_desc));
		if(ret < 0){
			debug("rx_desc write_back: failed to dma_write to %#lx",rxd_addr);
			continue;
		}

		ret = dma_write(rx_nt,rx_irq->addr,&rx_irq->data,sizeof(rx_irq->data));
		if(ret < 0){
			fprintf(stderr,"failed to generate Rx Interrupt\n");
			perror("dma_write for rx interrupt");
		}
		
		rx_desc++;
		rxd_ctl->desc_head += sizeof(struct descriptor);
		rxd_ctl->head++;

		if(rxd_ctl->head > DESC_ENTRY_SIZE-1){
			rx_desc = tap_rx_ctl->rx_desc;
			rxd_ctl->head = 0;
			rxd_ctl->desc_head = *rx_desc_base;
		};

		*rx_state = RX_STATE_READY;
	}
	
	pthread_join(tap_rx_ctl->tid,NULL);

	return NULL;
}

void mnic_alloc(struct nettlp_mnic *mnic)
{
	struct tx_desc_ctl *txdp;

	mnic->tx_desc_base = calloc(TX_QUEUES,sizeof(uintptr_t));
	mnic->rx_desc_base = calloc(RX_QUEUES,sizeof(uintptr_t));
	mnic->rx_desc_addr = calloc(RX_QUEUES,sizeof(uintptr_t));

	mnic->tx_irq = calloc(TX_QUEUES,sizeof(struct nettlp_msix));
	mnic->rx_irq = calloc(RX_QUEUES,sizeof(struct nettlp_msix));

	mnic->tx_desc_ctl = calloc(TX_QUEUES,sizeof(struct tx_desc_ctl));
	mnic->rx_desc_ctl = calloc(RX_QUEUES,sizeof(struct rx_desc_ctl));

	txdp = mnic->tx_desc_ctl;
	for(int i=0;i<TX_QUEUES;i++){
		txdp->tx_buf = calloc(DESC_ENTRY_SIZE,4096);
		txdp++;
	}

	for(int i=0;i<RX_QUEUES;i++){
		mnic->tx_desc[i] = calloc(DESC_ENTRY_SIZE,sizeof(struct descriptor));
		mnic->rx_desc[i] = calloc(DESC_ENTRY_SIZE,sizeof(struct descriptor));
	}

	//mnic->rx_dma_read_nt = calloc(RX_NT_SIZE,sizeof(struct nettlp));
}

void mnic_free(struct nettlp_mnic *mnic)
{
	int i;
	struct tx_desc_ctl *txdp;

	free(mnic->tx_desc_base);
	free(mnic->rx_desc_base);
	free(mnic->rx_desc_addr);

	free(mnic->tx_irq);
	free(mnic->rx_irq);

	txdp = mnic->tx_desc_ctl;
	for(i=0;i<TX_QUEUES;i++){
		free(txdp->tx_buf);
		txdp++;
	}

	free(mnic->tx_desc_ctl);
	free(mnic->rx_desc_ctl);

	for(i=0;i<RX_QUEUES;i++){
		free(mnic->tx_desc[i]);
		free(mnic->rx_desc[i]);
	}
}

void usage()
{
	printf("usage\n"
	       "    -r remote addr\n"
	       "    -l local addr\n"
	       "    -R remote host addr (not TLP NIC)\n"
	       "\n"
	       "    -t tunif name (default tap0)\n"
		);	
}

int main(int argc,char **argv)
{
        int opt,ret,tap_fd,i,n;
        char *ifname = "tap0";
	struct nettlp nt,nts[16],*nts_ptr[16];
	struct nettlp_cb cb;
	struct in_addr host;
	struct tap_rx_ctl tap_rx_ctl[4];
	struct nettlp_mnic mnic;	
	struct nettlp_msix msix[16];
	struct nettlp tap_rx_nt[4];
	struct tx_ctl tx_ctl[4];
	cpu_set_t target_cpu_set;
	//pthread_t rx_tid[8]; //tap_read_thread

	memset(&nt,0,sizeof(nt));

        while((opt = getopt(argc,argv,"t:r:l:R:")) != -1){
                switch(opt){
                case 't':
                        ifname = optarg;
                        break;
		case 'r':
			ret = inet_pton(AF_INET,optarg,&nt.remote_addr);
			if(ret < 1){
				perror("inet_pton");
				return -1;
			}
			break;
		case 'l':
			ret = inet_pton(AF_INET,optarg,&nt.local_addr);
			if(ret < 1){
				perror("inet_pton");
				return -1;
			}
			break;
		case 'R':
			ret = inet_pton(AF_INET,optarg,&host);
			if(ret < 1){
				perror("inet_pton");
				return -1;
			}

			nt.requester = nettlp_msg_get_dev_id(host);
			break;
		default:
			usage();
			return -1;
                }
        }

        tap_fd = tap_alloc(ifname);
        if(tap_fd < 0){
                perror("failed to allocate tap");
                return -1;
        }
        
        if(tap_up(ifname) < 0){
                perror("failed to up tap");
                return -1;
        }
        
	memset(&mnic,0,sizeof(mnic));
	mnic_f = &mnic;
	mnic.tap_fd = tap_fd;

	mnic_alloc(&mnic);

	for(n=0;n<4;n++){
		mnic.rx_state[n] = RX_STATE_INIT;
	}

	struct nettlp_msix *tx_irq = mnic.tx_irq;
	struct nettlp_msix *rx_irq = mnic.rx_irq;

	for(n=0;n<16;n++){
		nts[n] = nt;
 		nts[n].tag = n;
		nts_ptr[n] = &nts[n];
		nts[n].dir = DMA_ISSUED_BY_ADAPTER;

		ret = nettlp_init(nts_ptr[n]);
		if(ret < 0){
			debug("failed to init nettlp on tag %x\n",n);
			return ret;
		}
	}

	mnic.bar4_start = nettlp_msg_get_bar4_start(host);	
	if(mnic.bar4_start == 0){
		debug("failed to get BAR4 addr from %s\n",inet_ntoa(host));
		info("nettlp_msg_get_bar4_start");
		return -1;
	}

	ret = nettlp_msg_get_msix_table(host,msix,8);
	if(ret < 0){
		debug("faled to get msix table from %s\n",inet_ntoa(host));
		info("nettlp_msg_get_msix_table");
	}	

	for(i=0;i<8;i++){
		info("msix addr at %d is %#lx",i,msix[i].addr);
	}

	for(i=0;i<4;i++){
		*tx_irq = msix[i+4];
		*rx_irq = msix[i];
		tx_irq++;
		rx_irq++;
	}

	for(i=0;i<4;i++){
		memset(&mnic.tx_nt[i],0,sizeof(mnic.tx_nt[i]));
		memset(&mnic.rx_nt[i],0,sizeof(mnic.rx_nt[i]));
		memset(&tap_rx_nt[i],0,sizeof(tap_rx_nt[i]));
	}
	for(i=0;i<4;i++){
		mnic.tx_nt[i].tag = i;
		mnic.tx_nt[i].remote_addr = nt.remote_addr;
		mnic.tx_nt[i].local_addr = nt.local_addr;
		mnic.tx_nt[i].dir = DMA_ISSUED_BY_LIBTLP;
		mnic.tx_nt[i].requester = nt.requester;
		nettlp_init(&mnic.tx_nt[i]);

		mnic.rx_nt[i].tag = i+4;
		mnic.rx_nt[i].remote_addr = nt.remote_addr;
		mnic.rx_nt[i].local_addr = nt.local_addr;
		mnic.rx_nt[i].dir = DMA_ISSUED_BY_LIBTLP;
		mnic.rx_nt[i].requester= nt.requester;
		nettlp_init(&mnic.rx_nt[i]);

		tap_rx_nt[i].tag = i+8;
		tap_rx_nt[i].remote_addr = nt.remote_addr;
		tap_rx_nt[i].local_addr = nt.local_addr;
		tap_rx_nt[i].dir = DMA_ISSUED_BY_LIBTLP;
		tap_rx_nt[i].requester = nt.requester;
		nettlp_init(&tap_rx_nt[i]);
	}

	info("Device is %04x",nt.requester);
	info("BAR4 start adress is %#lx",mnic.bar4_start); 

	tx_irq = mnic.tx_irq;
	rx_irq = mnic.rx_irq;

	if(signal(SIGINT,signal_handler)==SIG_ERR){
		debug("failed to set signal");
		return -1;
	}

	for(i=0;i<4;i++){
		tap_rx_ctl[i].tap_fd = mnic.tap_fd;
		tap_rx_ctl[i].rx_state = &mnic.rx_state[i];
		tap_rx_ctl[i].rx_irq = mnic.rx_irq + i;
		tap_rx_ctl[i].rx_desc = mnic.rx_desc[i];
		tap_rx_ctl[i].rxd_ctl = mnic.rx_desc_ctl + i;
		tap_rx_ctl[i].rx_nt = &tap_rx_nt[i];
		tap_rx_ctl[i].rx_desc_base = mnic.rx_desc_base + i;

		if((ret = pthread_create(&tap_rx_ctl[i].tid,NULL,nettlp_mnic_tap_read_thread,&tap_rx_ctl[i])) != 0){
			debug("%d rx thread failed to be created",i);
		}

		CPU_ZERO(&target_cpu_set);
		CPU_SET(i+4,&target_cpu_set);
		pthread_setaffinity_np(tap_rx_ctl[i].tid,sizeof(cpu_set_t),&target_cpu_set);
	}

	for(i=0;i<4;i++){
		tx_ctl[i].offset = i;
		tx_ctl[i].mnic = &mnic;

		if((ret = pthread_create(&tx_ctl[i].tid,NULL,mnic_tx,&tx_ctl[i])) != 0){
			debug("%i tx thread failed to be created",i);
		}

		CPU_ZERO(&target_cpu_set);
		CPU_SET(i,&target_cpu_set);
		pthread_setaffinity_np(tx_ctl[i].tid,sizeof(cpu_set_t),&target_cpu_set);
	}

	info("start nettlp callback");
	memset(&cb,0,sizeof(cb));
	cb.mwr = nettlp_mnic_mwr;
	nettlp_run_cb(nts_ptr,16,&cb,&mnic);

        return 0;
}
