
#include "utils.h"

// https://en.wikipedia.org/wiki/Algorithms_for_calculating_variance#Welford's_online_algorithm
void    update_statistics(t_statistics* stats, double new_tt)
{
    stats->nbr_data++;

    if (ABS(stats->min_tt) < EPSILON || new_tt < stats->min_tt)
        stats->min_tt = new_tt;
    if (new_tt > stats->max_tt)
        stats->max_tt = new_tt;

    double delta = new_tt - stats->mean_tt;
    stats->mean_tt += delta / stats->nbr_data;
    double delta2 = new_tt - stats->mean_tt;
    stats->sq_diff_tt += delta * delta2;
    stats->std_dev_tt = sqrt(stats->sq_diff_tt / stats->nbr_data);
}

void print_statistics(char *host, t_statistics* stats)
{
    printf("--- %s ping statistics ---\n", host);
    double perc_loss = 100 * (double)(stats->nbr_pck_send - stats->nbr_pck_rcv) / stats->nbr_pck_send;
    printf("%d packets transmitted, %d packets received, %d%% packet loss\n",
        stats->nbr_pck_send, stats->nbr_pck_rcv, (int)perc_loss);
    printf("round-trip min/avg/max/stddev = %.3f/%.3f/%.3f/%.3f ms\n",
            stats->min_tt, stats->mean_tt, stats->max_tt, stats->std_dev_tt);
}