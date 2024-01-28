
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>

#include "icmp_packet.h"
#include "utils.h"
#include "libft.h"

static bool g_listen = true;
static bool g_keep_ping = true;

void handle_signal(int signum)
{
    if (signum == SIGALRM)
        g_listen = false;
    else if (signum == SIGINT)
    {
        g_listen = false;
        g_keep_ping = false;
    }
}

t_flags parse_arguments(int argc, char **argv)
{
    t_flags flags;
    ft_bzero(&flags, sizeof(t_flags));

    for (int i = 1; i < argc; ++i)
    {
        if (!ft_strcmp(argv[i], "-?") || !ft_strcmp(argv[i], "--help"))
            flags.help = 1;
        else if (!ft_strcmp(argv[i], "-v") || !ft_strcmp(argv[i], "--verbose"))
            flags.verbose = 1;
        else if (flags.host == NULL)
            flags.host = argv[i];
    }

    return flags;
}

void    print_help_message(void)
{
        printf("Usage: ping [OPTION...] HOST ...\n");
        printf("Send ICMP ECHO_REQUEST packets to network hosts.\n");
        printf("Options valid for all request types:\n\n");
        printf("  -v, --verbose              verbose output\n");
        printf("  -?, --help                 give this help list\n");

        printf("\n");
}

int main(int argc, char **argv)
{
    t_flags flags = parse_arguments(argc, argv);

    if (flags.help)
    {
        print_help_message();
        return 0;
    }

    if (flags.host == NULL)
    {
        fprintf(stderr, "ping: missing host operand\n");
        fprintf(stderr, "Try 'ping --help' or 'ping --usage' for more information.\n");
        return(EXIT_FAILURE);
    }

    // Check for root access
    if (getuid() != 0)
    {
        printf("%s: Lacking privilege for icmp socket.\n", argv[0]);
        return(EXIT_FAILURE);
    }

    // Convert address
    struct addrinfo* l_addr;
    if (!(l_addr = get_addr(argv[0], flags.host)))
        return EXIT_FAILURE;

    // Create raw socket
    int sock = create_raw_socket();
    if (sock == -1)
        return(EXIT_FAILURE);

    // Get host IP
    char hostname[NI_MAXHOST];
    if (getnameinfo(l_addr->ai_addr, l_addr->ai_addrlen, hostname, sizeof(hostname), NULL,
                0, NI_NUMERICHOST | NI_NUMERICSERV))
    {
        fprintf(stderr, "%s: could not resolve hostname\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Handle signals
    if (signal(SIGALRM, handle_signal) == SIG_ERR || signal(SIGINT, handle_signal) == SIG_ERR)
    {
        fprintf(stderr, "ping: error handling signals\n");
        return EXIT_FAILURE;
    }

    printf("PING %s (%s): %d data bytes", flags.host, hostname, ICMP_BODY_SIZE);
    if (flags.verbose)
        printf(", id 0x%04x = %d", getpid(), getpid());
    printf("\n");
    // Init statistics
    t_statistics stats;
    ft_bzero(&stats, sizeof(t_statistics));

    while (g_keep_ping)
    {
        // Create ICMP ECHO message
        t_icmp_request message;
        create_icmp_echo_request(&message);

        if (sendto(sock, &message, sizeof(message), 0, l_addr->ai_addr, l_addr->ai_addrlen) < -1)
        {
            printf("%s: %s", argv[0], strerror(errno));
            return EXIT_FAILURE;
        }
        stats.nbr_pck_send++;
        alarm(1);
        g_listen = true;

        // Receive packet
        while (g_listen)
        {
            int value = receive_icmp_message(argv[0], sock, &stats, flags.verbose);
            if (value == -1)
                return EXIT_FAILURE;
            if (value == 1)
                break;
        }
        while (g_listen) {}
    }

    print_statistics(flags.host, &stats);
    freeaddrinfo(l_addr);
    close(sock);
    return 0;
}
