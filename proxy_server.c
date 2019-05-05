#include <stdio.h>
#include <pcap.h> // PCAP 라이브러리 가져오기
#include <arpa/inet.h> // inet_ntoa 등 함수 포함
#include <netinet/in.h> // in_addr 등 구조체 포함
#include <net/if.h>
#include<sys/ioctl.h>
#include<stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#define BUF_SIZE 100
#define MAX_CLNT 256

void * handle_clnt(void * arg);
void send_msg(char * msg, int len);
void error_handling(char * msg);

int clnt_cnt=0;
int clnt_socks[MAX_CLNT];
pthread_mutex_t mutx;
char temp2[40];
char temp3[40];
char myip[40];
pcap_t *handle; // 핸들러
char *dev = "ens33"; // 자신의 네트워크 장비
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
struct bpf_program fp; // 필터 구조체
char *filter_exp = "port 9190"; // 필터 표현식
bpf_u_int32 mask; // 서브넷 마스크
bpf_u_int32 net; // 아이피 주소
struct pcap_pkthdr *header; // 패킷 관련 정보
const u_char *packet; // 실제 패킷
struct in_addr addr; // 주소 정보
u_int32_t target_ip;
u_int32_t m_ip;
#define ETHER_ADDR_LEN 6
struct sniff_ip;
struct sniff_tcp;
struct sniff_ethernet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
        u_short ether_type;
};

#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)
int payload_len;
void send_packet(const u_char *d_packet, pcap_t* handle){
	if(pcap_sendpacket(handle, d_packet, 66+payload_len) != 0)
		fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
}
struct sniff_ip {
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
        u_char ip_p; // IP 프로토콜 유형
        u_short ip_sum;
        struct in_addr ip_src; // 출발지 IP 주소
        struct in_addr ip_dst; // 목적지 IP 주소
};

typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        tcp_seq th_seq;
        tcp_seq th_ack;
        u_char th_offx2;
        #define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
        u_char th_flags;
        #define TH_FIN 0x01
        #define TH_SYN 0x02
        #define TH_RST 0x04
        #define TH_PUSH 0x08
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

struct sniff_ethernet *ethernet; // 이더넷 헤더
struct sniff_ip *ip;// IP 헤더
struct sniff_tcp *tcp; // TCP 혜더
char *payload; // 페이로드
struct sniff_tcp *dummy_tcp;
struct sniff_ip *dummy_ip;
u_int size_ip;
u_int size_tcp;
int first=1;// 이 패킷이 첫번째인지 아닌지 판단하는 용도의 변수
tcp_seq dummy_seq;

void parsing() {
        int i;
        ethernet = (struct sniff_ethernet*)(packet);
        ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	printf("%s\n", inet_ntoa(*(struct in_addr *)&target_ip));
        memcpy(&(ip->ip_dst.s_addr),&target_ip,sizeof(target_ip)); //정종민: 패킷의 목적지 ip를 타겟의 ip로 변경
	printf("%s\n", inet_ntoa(*(struct in_addr *)&target_ip));

	size_ip = IP_HL(ip)*4;
        tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	if(first==1){
		dummy_seq=ntohl(tcp->th_seq);//이 패킷이 첫번째일때(first==1)만 dummy_seq변수에 첫 패킷의 seq을 저장
		first++;
	}

	memcpy(&packet[38],&dummy_seq,sizeof(dummy_seq));
	size_tcp = TH_OFF(tcp)*4;
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
        payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
        if(payload_len == 0);
        else {
                printf("< 페이로드 데이터 >\n");
                for(int i = 1; i < payload_len; i++) {
                        printf("%c", payload[i - 1]);
                }
		printf("\n------------------------------------------------------\n");

        }
}
int isfiltered(){
	struct ifreq ifr;
	
	char temp[40];
	int s;
	int result;
	s=socket(AF_INET,SOCK_DGRAM,0);
	strncpy(ifr.ifr_name,"ens33",IFNAMSIZ);
	if(ioctl(s,SIOCGIFADDR, &ifr)<0){
		printf("Error");
	}
	else{
		inet_ntop(AF_INET,ifr.ifr_addr.sa_data+2,myip,sizeof(struct sockaddr));
	}
	strcpy(temp,inet_ntoa(ip->ip_src));
	if(strcmp(temp3,temp)!=0)
	{
		result=1;
		return result;
	}
	else
		result= 0;
	if(tcp->th_flags!=0x18){
		result=1;
		return result;
	}
	else
		result=0;
	return result;
}
struct sockaddr_in serv_adr, clnt_adr;
int clnt_adr_sz;

int main(int argc, char * argv[]) {
	printf("<-----PROXY SERVER----->\n");
	
	int serv_sock, clnt_sock;
    	int sock;
	struct sockaddr_in serv_addr;
	pthread_t t_id;
    	
	if(argc!=3)
    	{
        	printf("Usage : %s <port> <target ip>\n", argv[0]);
        	exit(1);
    	}
	strcpy(temp2,argv[2]);
	printf("targetip: %s\n", temp2);
    	target_ip=inet_addr(temp2);
	pthread_mutex_init(&mutx, NULL);
    	serv_sock=socket(PF_INET, SOCK_STREAM, 0);
    	memset(&serv_adr, 0, sizeof(serv_adr));
    	serv_adr.sin_family=AF_INET;
    	serv_adr.sin_addr.s_addr=htonl(INADDR_ANY);
    	serv_adr.sin_port=htons(atoi(argv[1]));
	
    	if(bind(serv_sock, (struct sockaddr*)&serv_adr, sizeof(serv_adr))==-1)
        	error_handling("bind() error");
    	if(listen(serv_sock, 5)==-1)
        	error_handling("listen() error");
	sock=socket(PF_INET,SOCK_STREAM,0);
	memset(&serv_addr,0,sizeof(serv_addr));
	serv_addr.sin_family=AF_INET;
	serv_addr.sin_addr.s_addr=inet_addr(argv[2]);
	serv_addr.sin_port=htons(atoi(argv[1]));

	while(1)
    	{

        	clnt_adr_sz=sizeof(clnt_adr);
		printf("Listeneing....\n");
        	clnt_sock=accept(serv_sock, (struct sockaddr*)&clnt_adr, &clnt_adr_sz);
        	printf("---proxy connected to client!!---\n");
		if(connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))==-1)
                error_handling("connect() error");
		printf("---proxy coneected to server!!---\n");
		pthread_mutex_lock(&mutx);
        	clnt_socks[clnt_cnt++]=clnt_sock;
        	pthread_mutex_unlock(&mutx);
        	pthread_create(&t_id, NULL, handle_clnt, (void*)&clnt_sock);
        	pthread_detach(t_id);
        	printf("Connected client IP: %s \n", inet_ntoa(clnt_adr.sin_addr));
    		strcpy(temp3,inet_ntoa(clnt_adr.sin_addr));

	}
    	close(serv_sock);
	return 0;
}
void * handle_clnt(void * arg)
{
        int clnt_sock=*((int*)arg);
        int str_len=0, i;
        char msg[BUF_SIZE];
        
        dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                printf("네트워크 장치를 찾을 수 없습니다.\n");
                return 0;
        }
        if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
                printf("장치의 주소를 찾을 수 없습니다.\n");
                return 0;
        }
        addr.s_addr = net;
        addr.s_addr = mask;
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                printf("장치를 열 수 없습니다.\n");
                printf("error message: %s", errbuf);
                return 0;
        }
        if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
                printf("필터를 적용할 수 없습니다.\n");
                return 0;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
                printf("필터를 세팅할 수 없습니다.\n");
                return 0;
        }
        printf("패킷을 감지합니다.\n");
        while(pcap_next_ex(handle, &header, &packet) == 1) {
                parsing();
		if(isfiltered()==1);
                else{
                printf("sending packet to target....\n");
		printf("srcip: %s, dstip: %s\n",inet_ntoa(ip->ip_src),inet_ntoa(ip->ip_dst));
		send_packet(packet,handle);
                }
        }
    	pthread_mutex_lock(&mutx);
    	for(i=0; i<clnt_cnt; i++)
    	{
        	if(clnt_sock==clnt_socks[i])
        	{
            	while(i++<clnt_cnt-1)
                	clnt_socks[i]=clnt_socks[i+1];
            	break;
        	}	
    	}
    	clnt_cnt--;
    	pthread_mutex_unlock(&mutx);
    	close(clnt_sock);
    	return NULL;
}
void error_handling(char * msg)
{
    	fputs(msg, stderr);
    	fputc('\n', stderr);
    	exit(1);
}
