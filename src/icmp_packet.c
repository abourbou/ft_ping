

#include <sys/time.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>

#include "libft.h"
#include "utils.h"
#include "icmp_packet.h"

static int g_seq = 0;


uint64_t get_current_time(void)
{
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    return current_time.tv_sec * 1e6 + current_time.tv_usec;
}

static unsigned short checksum(unsigned short *ptr, int nbytes) {
	unsigned long sum;
	unsigned short oddbyte;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
		sum += oddbyte;
	}
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return (unsigned short) ~sum;
}

int create_raw_socket(void)
{
    int    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (sock == -1)
    {
        fprintf(stderr, "Error socket creation: %s\n", strerror(errno));
        return -1;
    }

    return sock;
}

void create_icmp_echo_request(t_icmp_request *message)
{
    ft_bzero(message, sizeof(t_icmp_request));

    // Data
    uint64_t *timestamp = (void *)((uint8_t *)message + ICMP_HEADER_SIZE);
    *timestamp = get_current_time();

    // Header
    message->header.type = ICMP_ECHO;
    message->header.code = 0;
    message->header.checksum = 0;
    message->header.un.echo.id = htons(getpid());
    message->header.un.echo.sequence = htons(g_seq++);
    // Compute checksum
	message->header.checksum = checksum((void *)message, sizeof(t_icmp_request));
}

// Performs a DNS lookup and return every possible addresses
struct addrinfo* get_addr(char* program_name, char* addr_host)
{
    struct addrinfo hints = {0};
    struct addrinfo *results = NULL;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_RAW;
    hints.ai_protocol = IPPROTO_ICMP;

    int s = getaddrinfo(addr_host, NULL, &hints, &results);

    if (s != 0)
    {
        fprintf(stderr, "%s: unknown host\n", program_name);
        return NULL;
    }

    return results;
}

int receive_icmp_message(char *program_name, int sock, t_statistics* stats, bool verbose)
{
    char recv_packet[ICMP_ERROR_SIZE];
    ft_bzero(recv_packet, ICMP_ERROR_SIZE);
    struct iovec iov[1];
    iov[0].iov_base = recv_packet;
    iov[0].iov_len = sizeof(recv_packet);

    struct msghdr msg;
    ft_bzero(&msg, sizeof(struct msghdr));
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ssize_t bytes_received = recvmsg(sock, &msg, MSG_DONTWAIT);
    if (bytes_received == -1)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK )
        {
            printf("%s: %s\n", program_name, strerror(errno));
            return(-1);
        }
        return 0;
    }

    struct iphdr* iph = (void*)recv_packet;
    struct icmphdr *icmph;
    icmph = (void*)(recv_packet + IP_HEADER_SIZE);
    if(!is_our_message(iph, icmph))
        return 0;

    // Find ip address of the message
    char ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, ip_addr, INET_ADDRSTRLEN);

    // Check if the message is ok
    if (icmph->type != ICMP_ECHOREPLY)
    {
        handle_error(iph, icmph, ip_addr, bytes_received, verbose);
        return 1;
    }
    stats->nbr_pck_rcv++;
    uint64_t* start_timestamp = (void*)(recv_packet + IP_HEADER_SIZE + ICMP_HEADER_SIZE);

    double time_response = (get_current_time() - *start_timestamp) * 1e-3;

    printf("%ld bytes from %s: icmp_seq=%d ttl=%u time=%.3lf ms\n",
        bytes_received - IP_HEADER_SIZE, ip_addr, g_seq - 1, iph->ttl, time_response);

    update_statistics(stats, time_response);

    return (1);
}

bool is_our_message(struct iphdr* iph, struct icmphdr* icmph)
{
    if (iph->protocol == 1 && ntohs(icmph->un.echo.sequence) == g_seq - 1 && ntohs(icmph->un.echo.id) == getpid()
        && icmph->type != ICMP_ECHO)
        return true;
    return false;
}

void handle_error(struct iphdr* iph, struct icmphdr* icmph, char* ip_addr,
                    ssize_t bytes_received, bool verbose)
{
    printf("%ld bytes from %s: ", bytes_received - IP_HEADER_SIZE, ip_addr);
    if (icmph->type == ICMP_DEST_UNREACH)
    {
        if (icmph->code == ICMP_NET_UNREACH)
            printf("Destination Net Unreachable");
        if (icmph->code == ICMP_HOST_UNREACH)
            printf("Destination Host Unreachable");
        if (icmph->code == ICMP_PROT_UNREACH)
            printf("Destination Protocol Unreachable");
        if (icmph->code == ICMP_PORT_UNREACH)
            printf("Destination Port Unreachable");
        if (icmph->code == ICMP_FRAG_NEEDED)
            printf("Fragmentation needed and DF set");
        if (icmph->code == ICMP_SR_FAILED)
            printf("Source Route Failed");
        if (icmph->code == ICMP_NET_UNKNOWN)
            printf("Network Unknown");
        if (icmph->code == ICMP_HOST_UNKNOWN)
            printf("Host Unknown");
        if (icmph->code == ICMP_HOST_ISOLATED)
            printf("Host Isolated");
        if (icmph->code == ICMP_NET_UNR_TOS)
            printf("Destination Network Unreachable At This TOS");
        if (icmph->code == ICMP_HOST_UNR_TOS)
            printf("Destination Host Unreachable At This TOS");
    }
    else if(icmph->type == ICMP_REDIRECT)
    {
        if (icmph->code == ICMP_REDIR_NET)
            printf("Redirect Network");
        if (icmph->code == ICMP_REDIR_HOST)
            printf("Redirect Host");
        if (icmph->code == ICMP_REDIR_NETTOS)
            printf("Redirect Type of Service and Network");
        if (icmph->code == ICMP_REDIR_HOSTTOS)
            printf("Redirect Type of Service and Host");
    }
    else if (icmph->type == ICMP_TIME_EXCEEDED)
    {
        if(icmph->code == ICMP_EXC_TTL)
            printf("Time to live exceeded");
        if(icmph->code == ICMP_EXC_FRAGTIME)
            printf("Frag reassembly time exceeded");
    }
    printf("\n");
    if (verbose)
    {
        printf("IP hdr Dump:\n");
        unsigned char *p_iph = (void*)iph;
        for (size_t i = 0; i < sizeof(struct iphdr); i+=2)
            printf(" %02x%02x", p_iph[i], p_iph[i + 1]);
        printf("\n");
        printf("Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");

        // Print readable informations
        uint16_t frag_off_bit = iph->frag_off;
        short flag = *((char*)(&frag_off_bit) + 1);
        uint16_t offset = *((char*)(&frag_off_bit) + 3);
        char src_ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, src_ip_addr, INET_ADDRSTRLEN);
        char dest_ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph->saddr, dest_ip_addr, INET_ADDRSTRLEN);

        printf(" %d  %d  %02d %04d %x   %hhx %04d  %01d   %01d %x %s  %s\n",
            iph->version, iph->ihl, iph->tos, ntohs(iph->tot_len),
            ntohs(iph->id), flag, offset,
            iph->ttl, iph->protocol, ntohs(iph->check), src_ip_addr, dest_ip_addr);

        printf("ICMP: type %d, code %d, size %ld, id 0x%04x, seq 0x%04x\n",
            icmph->type, icmph->code, bytes_received - IP_HEADER_SIZE,
            ntohs(icmph->un.echo.id), ntohs(icmph->un.echo.sequence));
    }
}