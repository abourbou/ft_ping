

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

static int _seq = 0;


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
    message->header.un.echo.id = getpid();
    message->header.un.echo.sequence = _seq++;
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

int receive_icmp_message(char *program_name, int sock, char *hostname, t_statistics* stats)
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

    // Check if the message is ok
    if (icmph->type != ICMP_ECHOREPLY)
    {
        printf("Error in the ICMP response, not ECHOREPLY\n");
        return 1;
    }
    stats->nbr_pck_rcv++;
    uint64_t* start_timestamp = (void*)(recv_packet + IP_HEADER_SIZE + ICMP_HEADER_SIZE);

    double time_response = (get_current_time() - *start_timestamp) * 1e-3;

    printf("%ld bytes from %s: icmp_seq=%d ttl=%u time=%.3lf ms\n",
        bytes_received - IP_HEADER_SIZE, hostname, _seq - 1, iph->ttl, time_response);

    update_statistics(stats, time_response);

    return (1);
}

bool is_our_message(struct iphdr* iph, struct icmphdr* icmph)
{
    if (iph->protocol == 1 && icmph->un.echo.sequence == _seq - 1 && icmph->un.echo.id == getpid()
        && icmph->type != ICMP_ECHO)
        return true;
    return false;
}