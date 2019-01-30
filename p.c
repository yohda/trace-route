#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE 1024	 
#define TIME_OUT 1   // 최대 1초만 응답을 기다린다.
#define TTL_LIMIT 30 // TTL 최대 30으로 제한한다.

void handle_status(int, int, char*);
int socket_set_option (int , int , int , const void*);
int in_cksum(u_short*, int);
char *inet_ntoa64(struct in_addr);
 
int main(int argc, char **argv)
{
	struct timeval t_time;
	int sock, status = 0;
	struct icmp *p, *rp;
	struct sockaddr_in to, from;
	struct ip *ip;
	char ack[BUF_SIZE], *host;
	char msg[BUF_SIZE];
	socklen_t fromlen;
	int hdr_len, ttl_s, seq = 15;
	struct hostent *domain;
	char *ipchar = NULL;

	if(argc != 2){
		fprintf(stderr, "Usage: %s [IP or DOMAIN]\n", argv[0]);
		exit(0);
	}
	
	if((domain=gethostbyname(argv[1])) == NULL) {  
		perror("host error: ");
		handle_status(status, sock, argv[1]);
	}

	ipchar = inet_ntoa64(*((struct in_addr *)domain->h_addr));
	sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); // IPv4를 이용하고, 3계층인 ICMP를 조작해야 하므로, Raw소켓을 이용한다.
	if(sock < 0){
		perror("socket error: ");
		handle_status(status, sock, ipchar);
		exit(0);
	}

	/* 이거 왜 있는거지??... 밑에 for문안에서 다시 설정을 하는데...  */
	/*
	if(setsockopt (sock, SOL_IP, IP_TTL, &ttl_e, sizeof(ttl_e)) < 0) {
		perror ("setsockopt IP_TTL");
		handle_status(status, sock, ipchar);
	}
 	*/

	t_time.tv_sec = TIME_OUT;
	t_time.tv_usec = 0;
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &t_time, sizeof(struct timeval)); // 송신 대기(blocking)를 1초로 제한한다.
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &t_time, sizeof(struct timeval)); // 수신 대기(blocking)를 1초로 제한한다.

	if(argv[1][0] < 'A')
		printf("traceroute to (%s), %d hops max\n", ipchar, TTL_LIMIT);
	else
		printf("traceroute to %s (%s), %d hops max\n", argv[1], ipchar, TTL_LIMIT);
	
	/* TTL 값을 하나씩 증가시켜 보낸다. ICMP로 보내기 때문에 응답이 오면, 거쳐가는 라우터의 IP를 알 수 있다. */
	for(ttl_s = 1; ttl_s <= TTL_LIMIT; ttl_s++, seq++) {
		ipchar = inet_ntoa64(*((struct in_addr *)domain->h_addr));
 
		/* IPPROTO_IP or SOL_IP  */
        	/* socket설정에서 ttl을 1씩 계속 증가시킨다. 가장 핵심적인 부분인 것 같다. */
		if (setsockopt (sock, IPPROTO_IP, IP_TTL, &ttl_s, sizeof(ttl_s)) < 0) 
			perror ("setsockopt IP_TTL");
 
		memset(msg, 0x00, sizeof(msg));
		memset(ack, 0x00, sizeof(ack));
 
		p = (struct icmp *)msg;
		p->icmp_type=ICMP_ECHO;
		p->icmp_code=0;
		p->icmp_cksum=0;
		p->icmp_seq=seq;
		p->icmp_id=getpid();
		p->icmp_cksum = in_cksum((u_short *)p, 1024);
 
		inet_aton (ipchar, &to.sin_addr);
		to.sin_family = AF_INET;
 
        	/* MSG_DONTWAIT = 전송 준비 전에 대기 상태가 필요하다면, 기다리지 않고 -1을 반환하면서 복귀 */
		if (sendto(sock, p, sizeof(*p), MSG_DONTWAIT, (struct sockaddr *)&to, sizeof(to)) == -1) {
			perror("send error: ");
			handle_status(status, sock, ipchar);
		}
 
		fromlen = sizeof(from);
		if (recvfrom(sock, ack, sizeof(ack), 0, (struct sockaddr *)&from, &fromlen) == -1) {
			printf(" %d * * *\n", ttl_s);
			continue;
		}
		
		ip = (struct ip *)ack;
		hdr_len = ip->ip_hl*4;
		rp = (struct icmp *)(ack+hdr_len);
				
		/* 데이터를 수신하는 경우, 중간에 라우터가 ICMP메세지를 받은 것이 된다. 그래서 recvfrom에서 from에서 중간 라우터의 ip를 가져올 수 있다. */
		if(ttl_s == 1)
			printf(" %d _gateway (%s)\n", ttl_s, inet_ntoa64(from.sin_addr));
		else
			printf(" %d %s\n", ttl_s, inet_ntoa64(from.sin_addr));
 
		/* Identifier(Id)와 Sequence Number(Seq)는 내가 보낸 ICMP 응답에 대한 메세제인지를 확인하기 위한 목적으로 사용한다.  */		
		if(rp->icmp_type == ICMP_ECHOREPLY && p->icmp_id == rp->icmp_id && rp->icmp_seq == seq) {
			status = 1;
			handle_status(status, sock, ipchar);
		}
		status = 0;
 
	}
	
	return 0;
}
 
void handle_status(int status, int sock, char* domain_or_ip){
	if (status == 1)
		printf("\nTRACEROUTE TO %s: OK\n", domain_or_ip);
	else 
		printf("\nTRACEROUTE TO %s: FAIL\n", domain_or_ip);
 
	if(sock > 0) close(sock);
	exit(0);
}

int in_cksum( u_short *p, int n ){
    register u_short answer;
    register long sum = 0;
    u_short odd_byte = 0;

    while(n > 1){
        sum += *p++;
        n -= 2;
    }

    if(n == 1){
        *( u_char* )( &odd_byte ) = *( u_char* )p;
        sum += odd_byte;
    }

    sum = ( sum >> 16 ) + ( sum & 0xffff );    
    sum += ( sum >> 16 );                    
    answer = ~sum;                           
    
    return ( answer );
}

char *inet_ntoa64(struct in_addr ina)
{
	static char buf[4*sizeof("123")];
	unsigned char *ucp = (unsigned char *)&ina;
 
	sprintf(buf, "%d.%d.%d.%d",
			ucp[0] & 0xff,
			ucp[1] & 0xff,
			ucp[2] & 0xff,
			ucp[3] & 0xff);
	return buf;
}
