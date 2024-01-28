

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
    message->header.un.echo.id = htons((uint16_t)getpid());
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
    struct icmphdr *icmph = (void*)(recv_packet + IP_HEADER_SIZE);
    // Find ip address of the message
    char ip_addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &iph->saddr, ip_addr, INET_ADDRSTRLEN);

    if (iph->protocol != IPPROTO_ICMP || icmph->type == ICMP_ECHO)
        return 0;
    else if (icmph->type != ICMP_ECHOREPLY)
    {
        struct icmphdr* icmph_data = (void*)(recv_packet + IP_HEADER_SIZE * 2 + ICMP_HEADER_SIZE);
        if(!is_our_message(icmph_data))
            return 0;
        handle_error(iph, icmph, ip_addr, bytes_received, verbose);
        return 1;
    }
    else if(!is_our_message(icmph))
        return 0;

    stats->nbr_pck_rcv++;
    uint64_t* start_timestamp = (void*)(recv_packet + IP_HEADER_SIZE + ICMP_HEADER_SIZE);

    double time_response = (get_current_time() - *start_timestamp) * 1e-3;

    printf("%ld bytes from %s: icmp_seq=%d ttl=%u time=%.3lf ms\n",
        bytes_received - IP_HEADER_SIZE, ip_addr, g_seq - 1, iph->ttl, time_response);

    update_statistics(stats, time_response);

    return (1);
}

bool is_our_message(struct icmphdr* icmph)
{
    if (ntohs(icmph->un.echo.sequence) == g_seq - 1 && ntohs(icmph->un.echo.id) == (uint16_t)getpid())
        return true;
    return false;
}

void handle_error(struct iphdr* iph, struct icmphdr* icmph, char* ip_addr,
                    ssize_t bytes_received, bool verbose)
{
    fprintf(stderr, "%ld bytes from %s: ", bytes_received - IP_HEADER_SIZE, ip_addr);
    if (icmph->type == ICMP_DEST_UNREACH)
    {
        if (icmph->code == ICMP_NET_UNREACH)
            fprintf(stderr, "Destination Net Unreachable");
        if (icmph->code == ICMP_HOST_UNREACH)
            fprintf(stderr, "Destination Host Unreachable");
        if (icmph->code == ICMP_PROT_UNREACH)
            fprintf(stderr, "Destination Protocol Unreachable");
        if (icmph->code == ICMP_PORT_UNREACH)
            fprintf(stderr, "Destination Port Unreachable");
        if (icmph->code == ICMP_FRAG_NEEDED)
            fprintf(stderr, "Fragmentation needed and DF set");
        if (icmph->code == ICMP_SR_FAILED)
            fprintf(stderr, "Source Route Failed");
        if (icmph->code == ICMP_NET_UNKNOWN)
            fprintf(stderr, "Network Unknown");
        if (icmph->code == ICMP_HOST_UNKNOWN)
            fprintf(stderr, "Host Unknown");
        if (icmph->code == ICMP_HOST_ISOLATED)
            fprintf(stderr, "Host Isolated");
        if (icmph->code == ICMP_NET_UNR_TOS)
            fprintf(stderr, "Destination Network Unreachable At This TOS");
        if (icmph->code == ICMP_HOST_UNR_TOS)
            fprintf(stderr, "Destination Host Unreachable At This TOS");
    }
    else if(icmph->type == ICMP_REDIRECT)
    {
        if (icmph->code == ICMP_REDIR_NET)
            fprintf(stderr, "Redirect Network");
        if (icmph->code == ICMP_REDIR_HOST)
            fprintf(stderr, "Redirect Host");
        if (icmph->code == ICMP_REDIR_NETTOS)
            fprintf(stderr, "Redirect Type of Service and Network");
        if (icmph->code == ICMP_REDIR_HOSTTOS)
            fprintf(stderr, "Redirect Type of Service and Host");
    }
    else if (icmph->type == ICMP_TIME_EXCEEDED)
    {
        if(icmph->code == ICMP_EXC_TTL)
            fprintf(stderr, "Time to live exceeded");
        if(icmph->code == ICMP_EXC_FRAGTIME)
            fprintf(stderr, "Frag reassembly time exceeded");
    }
    fprintf(stderr, "\n");
    if (verbose)
    {
        fprintf(stderr, "IP hdr Dump:\n");
        unsigned char *p_iph = (void*)((char*)iph + IP_HEADER_SIZE + ICMP_HEADER_SIZE);
        struct iphdr *iph_data = (void*)p_iph;
        for (size_t i = 0; i < sizeof(struct iphdr); i+=2)
            fprintf(stderr, " %02x%02x", p_iph[i], p_iph[i + 1]);
        fprintf(stderr, "\n");
        fprintf(stderr, "Vr HL TOS  Len   ID Flg  off TTL Pro  cks      Src      Dst     Data\n");

        // Print readable informations
        uint16_t frag_off_backward = ntohs(iph_data->frag_off);
        uint8_t flag = (frag_off_backward >> 13) & 0x07;
        uint32_t offset = frag_off_backward & 0x1fff;
        char src_ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph_data->saddr, src_ip_addr, INET_ADDRSTRLEN);
        char dest_ip_addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &iph_data->daddr, dest_ip_addr, INET_ADDRSTRLEN);

        fprintf(stderr, " %d  %d  %02d %04x %x   %hhx %04d  %02d  %02d %x %s  %s\n",
            iph_data->version, iph_data->ihl, iph_data->tos, ntohs(iph_data->tot_len),
            ntohs(iph_data->id), flag, offset,
            iph_data->ttl, iph_data->protocol, ntohs(iph_data->check), src_ip_addr, dest_ip_addr);

        struct icmphdr* icmph_data = (void*)((char*)iph_data + IP_HEADER_SIZE);
        fprintf(stderr, "ICMP: type %d, code %d, size %ld, id 0x%04x, seq 0x%04x\n",
            icmph_data->type, icmph_data->code, bytes_received - IP_HEADER_SIZE * 2 - ICMP_HEADER_SIZE,
            ntohs(icmph_data->un.echo.id), ntohs(icmph_data->un.echo.sequence));
    }
}