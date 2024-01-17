
#include <string.h>
#include <errno.h>

#include "utils.h"
#include "libft.h"

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
        else
            flags.host = argv[i];
    }

    return flags;
}

void    print_help_message(void)
{
        ft_printf("Usage: ping [OPTION...] HOST ...\n");
        ft_printf("Send ICMP ECHO_REQUEST packets to network hosts.\n");
        ft_printf("Options valid for all request types:\n\n");
        ft_printf("  -v, --verbose              verbose output\n");
        ft_printf("  -?, --help                 give this help list\n");

        ft_printf("\n");
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
        ft_printf("ping: missing host operand\n");
        ft_printf("Try 'ping --help' or 'ping --usage' for more information.\n");
        return 64;
    }

    return 0;
}