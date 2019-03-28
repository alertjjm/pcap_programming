#include <stdio.h>
#include <pcap.h> // PCAP 라이브러리 가져오기
#include <arpa/inet.h> // inet_ntoa 등 함수 포함
#include <netinet/in.h> // in_addr 등 구조체 포함
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

pcap_t *handle; // 핸들러
char *dev = "ens33"; // 자신의 네트워크 장비
char errbuf[PCAP_ERRBUF_SIZE]; // 오류 메시지를 저장하는 버퍼
// struct bpf_program fp; // 필터 구조체
// char *filter_exp = "port 9190"; // 필터 표현식
// bpf_u_int32 mask; // 서브넷 마스크
// bpf_u_int32 net; // 아이피 주소
// struct pcap_pkthdr *header; // 패킷 관련 정보
// const u_char *packet; // 실제 패킷
// struct in_addr addr; // 주소 정보
u_int32_t target_ip;

#define ETHER_ADDR_LEN 6
#define PROTOCOL_LEN 4

struct e_i_t_packet {
        u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC 주소
        u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC 주소
        u_short ether_type;
        
        uint16_t ip_buf;
	uint16_t total_len;
        u_short ip_id;
        u_short ip_off;
        #define IP_RF 0x8000
        #define IP_DF 0x4000
        #define IP_MF 0x2000
        #define IP_OFFMASK 0x1fff
        u_char ip_ttl;
        u_char ip_p; // IP 프로토콜 유형
        u_short ip_sum;
        uint8_t src_ip[PROTOCOL_LEN]; // 출발지 IP 주소
        uint8_t dst_ip[PROTOCOL_LEN]; // 목적지 IP 주소

        u_short th_sport; // 출발지 TCP 주소
        u_short th_dport; // 목적지 TCP 주소
        u_int th_seq;
        u_int th_ack;
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

void send_packet(struct e_i_t_packet packet, pcap_t* handle)
{
	uint8_t *p = (uint8_t *)&packet;
	if(pcap_sendpacket(handle, p, 54) != 0)
		fprintf(stderr, "\nError sending the packet! : %s\n", pcap_geterr(handle));
}



struct e_i_t_packet request_packet(struct e_i_t_packet packet, uint8_t * my_ipaddr)
{

        packet.ether_shost[0]=0x00; // 출발지 MAC 주소
        packet.ether_shost[1]=0x0c;
        packet.ether_shost[2]=0x29;
        packet.ether_shost[3]=0x57;
        packet.ether_shost[4]=0x1d;
        packet.ether_shost[5]=0x1c;

        packet.ether_type=htons(0x0800);
        
        packet.ip_buf=htons(0x4500);
	packet.total_len=htons(0x0028);

        packet.ip_id=0x0000;
        packet.ip_off=0x0000;
        
        packet.ip_ttl=0x40;
        packet.ip_p=0x06; // IP 프로토콜 유형
        packet.ip_sum=0x0000;
       
        // 출발지 IP 주소
         // 목적지 IP 주소

        packet.src_ip[0] = my_ipaddr[0];
        packet.src_ip[1] = my_ipaddr[1];
        packet.src_ip[2] = my_ipaddr[2];
        packet.src_ip[3] = my_ipaddr[3];

       
        packet.th_dport=ntohs(0x23e6); // 목적지 TCP 주소

        packet.th_seq=0x00000000;
        packet.th_ack=0x00000000;
        packet.th_offx2=0xa0;
        
        packet.th_flags=0x02;
        
        packet.th_win=htons(0x7210);
        packet.th_sum=0x0000;
        packet.th_urp=0x0000;
    
        printf("finish make packet...\n\n");

        return packet;
}

int main(int argc, char* argv[]) {

    struct e_i_t_packet packet;
    char temp[50];
    printf("target ip address: ");
	scanf("%s", temp);
	target_ip=inet_addr(temp);

     uint8_t my_ipaddr[4];


     my_ipaddr[0]=0xc0;
     my_ipaddr[1]=0xa8;
     my_ipaddr[2]=0x4d;
     my_ipaddr[3]=0x91;


	dev = pcap_lookupdev(errbuf);
        if (dev == NULL) {
                printf("네트워크 장치를 찾을 수 없습니다.\n");
                return 0;
        }
        printf("나의 네트워크 장치: %s\n", dev);
       
        handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == NULL) {
                printf("장치를 열 수 없습니다.\n");
                printf("error message: %s", errbuf);
		return 0;
        }


        
        while(1)
{   
    printf("Let's Make packet....\n\n");

        packet=request_packet(packet, my_ipaddr);
        send_packet(packet, handle);
        sleep(1);
}

	return 0;
}

