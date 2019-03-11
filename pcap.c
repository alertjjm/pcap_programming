#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<netinet/in.h>
pcap_t * handle;
char* dev="eth0";
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp;
char* filter_exp ="port 80";
bpf_u_int32 mask; //subnetmask
bpf_u_int32 net; //ipaddress
struct pcap_pkthdr* header; //packet information
const u_char* packet; //real packet
struct in_addr addr;

/* ddddddddddddddddddddddddddddddddddddddd*/

int main(void){
	dev=pcap_lookupdev(errbuf);
	if(dev==NULL){
		printf("network device not found!\n");
		return 0;
	}
	printf("my network device: %s\n",dev);
	if(pcap_lookupnet(dev,&net, &mask, errbuf)==-1){
		printf("cannot find address\n");
		return 0;
	}
	addr.s_addr=net;
	printf("my ip address: %s\n", inet_ntoa(addr));
	addr.s_addr=mask;
	printf("my subnet ip address: %s\n", inet_ntoa(addr));
	return 0;
}
