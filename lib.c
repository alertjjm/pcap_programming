#include<libnet.h>
#include<pcap.h>
#define GNIP_FILTER "icmp[0] = 0"
void usage(char * a){
}
int main(int argc, char **argv){
	libnet_t *l =NULL;
	pcap_t *p=NULL;
	u_int8_t *packet;
	u_int32_t dst_ip, src_ip;
	u_int16_t id, seq, count;
	int c, interval=0,pcap_fd, timed_out;
	u_int8_t loop, *payload=NULL;
	u_int32_t payload_s =0;
	libnet_ptag_t icmp=0, ip=0;
	char *device =NULL;
	fd_set read_set;
	struct pcap_pkthdr pc_hdr;
	struct bpf_program filter_code;
	bpf_u_int32 local_net, netmask;
	struct libnet_ipv4_hdr *ip_hdr;
	struct libnet_icmpv4_hdr *icmp_hdr;
	char errbuf[LIBNET_ERRBUF_SIZE];
	while((c=getopt(argc, argv,"I:i:c:"))!=EOF){
		switch(c){
			case 'I':
				device=optarg;
				break;
			case 'i':
				interval=atoi(optarg);
				break;
			case 'c':
				count=atoi(optarg);
				break;
		}
	}
	c=argc-optind;
	if(c!=1){
		usage(argv[0]);
		exit(1);
	}
}
