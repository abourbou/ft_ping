

#include <sys/time.h>
#include <netinet/ip.h>
#include <stdint.h>

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
        ft_printf("Error socket creation: %s\n", strerror(errno));
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
        ft_printf("%s: %s\n", program_name, gai_strerror(s));
        return NULL;
    }

    return results;
}