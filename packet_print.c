#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> // For ETH_P_IP
#include "myheader.h" // 구조체 정의를 포함한 헤더 파일

// MAC 주소를 출력하는 함수
void print_mac_address(u_char *mac) {
    for(int i = 0; i < 6; i++) {
        printf("%02x", mac[i]);
        if(i < 5)
            printf(":");
    }
}

// 패킷 콜백 함수
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;
    if (ntohs(eth->ether_type) == 0x0800) { // IP 패킷 여부 확인
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        if(ip->iph_protocol == IPPROTO_TCP) {
            struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + ip->iph_ihl*4);
            
            printf("Ethernet Header: \n");
            printf("   src mac: ");
            print_mac_address(eth->ether_shost);
            printf("\n   dst mac: ");
            print_mac_address(eth->ether_dhost);
            printf("\n");
            
            printf("IP Header: \n");
            printf("   src ip: %s\n", inet_ntoa(ip->iph_sourceip));
            printf("   dst ip: %s\n", inet_ntoa(ip->iph_destip));
            
            printf("TCP Header: \n");
            printf("   src port: %d\n", ntohs(tcp->tcp_sport));
            printf("   dst port: %d\n", ntohs(tcp->tcp_dport));
            
            // 메시지 출력
            int header_size = sizeof(struct ethheader) + ip->iph_ihl*4 + TH_OFF(tcp)*4;
            int data_size = ntohs(ip->iph_len) - (ip->iph_ihl*4 + TH_OFF(tcp)*4);
            if(data_size > 0) {
                printf("Message: ");
                const u_char *data = packet + header_size;
                for(int i = 0; i < data_size && i < 50; i++) { // 50바이트까지만 출력
                    printf("%02x ", data[i]);
                }
                printf("\n");
            }
            printf("------------------------------------------------\n");
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;
    bpf_u_int32 mask;

    // 네트워크 주소와 마스크 가져오기
    if (pcap_lookupnet("ens33", &net, &mask, errbuf) == -1) {
        fprintf(stderr, "네트워크 주소 및 마스크를 찾을 수 없습니다: %s\n", errbuf);
        net = 0;
        mask = 0;
    }

    // NIC에 대한 live pcap 세션 열기
    handle = pcap_open_live("ens33", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live() 실패: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // BPF(pseudo-code)로 필터 표현식 컴파일
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "pcap_compile() 실패: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // 컴파일된 필터 적용
    if (pcap_setfilter(handle, &fp) != 0) {
        fprintf(stderr, "pcap_setfilter() 실패: %s\n", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    // 패킷 캡처 시작
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle); // 핸들 닫기
    return 0;
}
