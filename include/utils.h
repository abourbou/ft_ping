
#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdbool.h>
#include <math.h>

#define EPSILON 1e-9
#define ABS(x) (x < 0 ? -1 * x : x)

typedef struct s_flags
{
    char* host;
    int help;
    int verbose;
} t_flags;

typedef struct s_statistics {
    int     nbr_pck_send;
    int     nbr_pck_rcv;
    // Time travel statistics
    int     nbr_data;
    double  min_tt;
    double  max_tt;
    double  sq_diff_tt;
    double  std_dev_tt;
    double  mean_tt;
} t_statistics;

void    update_statistics(t_statistics* stats, double new_tt);
void    print_statistics(char *host, t_statistics* stats);

#endif