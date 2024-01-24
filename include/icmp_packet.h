
#ifndef ICMP_PACKET_H
#define ICMP_PACKET_H

#include <stddef.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>

// Check https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
#define ICMP_BODY_SIZE 56
#define ICMP_HEADER_SIZE sizeof(struct icmphdr)
#define ICMP_TOTAL_SIZE (ICMP_BODY_SIZE + ICMP_HEADER_SIZE)

// Check https://en.wikipedia.org/wiki/Ping_(networking_utility)
#define IP_HEADER_SIZE (sizeof(struct iphdr))
// Size of an ICMP error
#define ICMP_ERROR_SIZE ((IP_HEADER_SIZE + ICMP_HEADER_SIZE) * 2 + ICMP_BODY_SIZE + 1)

typedef struct s_icmp_request
{
    struct icmphdr header;
    uint8_t data[ICMP_BODY_SIZE];
} t_icmp_request;

uint64_t            get_current_time(void);
int                 create_raw_socket(void);
void                create_icmp_echo_request(t_icmp_request *message);
struct addrinfo*    get_addr(char* program_name, char* addr_host);
int                 receive_icmp_message(char *program_name, int sock, char *hostname);
bool                is_our_message(struct iphdr* iph, struct icmphdr* icmph);
#endif