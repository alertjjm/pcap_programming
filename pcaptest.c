#include<stdio.h>
#include<pcap.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#define ETHER_ADDR_LEN 6
/*
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip->ip_vhl) >> 4)
*/
void parsing();
pcap_t * handle;
char* dev="eth0";
char errbuf[PCAP_ERRBUF_SIZE];
struct bpf_program fp; //filter
char* filter_exp ="port 80";
bpf_u_int32 mask; //subnetmask
bpf_u_int32 net; //ipaddress
struct pcap_pkthdr* header; //packet information
const u_char* packet; //real packet
struct in_addr addr;

/* ddddddddddddddddddddddddddddddddddddddd*/
struct sniff_ethernet{
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ehter_type;
};
struct sniff_ip{
	u_char ip_vhl;
	u_char ip_tos;
	u_short ip_len;
	u_short ip_id;
	u_short ip_off;
	#define IP_RF 0x8000
	#define IP_DF 0x4000
	#define IP_MF 0x2000
	#define IP_OFFMASK 0x1fff
	u_char ip_ttl;
	u_char ip_p;
	u_short ip_sum;
	struct in_addr ip_src;
	struct in_addr ip_dst;
};
typedef u_int tcp_seq;
struct sniff_tcp{

	u_short th_sport;
	u_short th_dport;
	tcp_seq th_seq;
	tcp_seq th_ack;
	u_char th_offx2;
	#define TH_OFF(th) ((th)->th_offx2 &0xf0>>4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;
	u_short th_sum;
	u_short th_urp;
};

#define SIZE_ETHERNET 14
struct sniff_ethernet *ethernet;
struct sinff_ip *ip;
struct sniff_tcp *tcp;
char* payload;
u_int size_ip;
u_int size_tcp;
int main(void){
	handle=pcap_open_live(dev,BUFSIZ,1,1000,errbuf);
	if(handle==NULL){
		printf("cannot open device\n");
		return 0;
	}
	if(pcap_compile(&handle, &fp, filter_exp,0,net)==-1){
		printf("cannot apply filter\n");
		return 0;
	}
	if(pcap_setfilter(handle, &fp)==-1){
		printf("cannot set filter\n");
		return 0;
	}
	while(pcap_next_ex(handle, &header, &packet)>=0){
		parsing();
	}
}
void parsing(){
	struct sniff_tcp dummy;
	printf("--------------------------------------------\n");
	int i;
	ethernet=(struct sniff_ethernet*)(packet);
	printf("MAC start address: ");
	for(i=0; i<ETHER_ADDR_LEN; i++){
		printf("%02x ",ethernet->ether_shost[i]);
	}
	printf("\nMAC destination address: ");
	for(i=0; i<ETHER_ADDR_LEN; i++){
		printf("%02x ",ethernet->ether_dhost[i]);
	}
	ip=(struct sniff_ip*)(packet+SIZE_ETHERNET);
	size_ip=IP_HL(ip)*4;
	printf("\nIP start address: %s\n", inet_ntoa(ip->ip_src));
	printf("IP destinatinon address: %s\n", inet_ntoa(ip->ip_dst));
	tcp=(struct sniff_tcp*)(packet+SIZE_ETHERNET+size_ip);
	size_tcp=TH_OFF(tcp)*4;
	memcpy(&dummy,tcp,size_tcp);
	dummy->seq=htonl(00000000);
	memcpy(tcp,&dummy,size_tcp);
	printf("start port: %d\n", ntohs(tcp->th_sport));
	printf("destination port: %d\n", ntohs(tcp->th_dport));
	printf("--------------------------------------------\n");







}
