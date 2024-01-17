/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_math_tools.c                                  .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:53:25 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:20:19 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

int		ft_min(int nbr1, int nbr2)
{
	if (nbr1 < nbr2)
		return (nbr1);
	else
		return (nbr2);
}

int		ft_max(int nbr1, int nbr2)
{
	if (nbr1 > nbr2)
		return (nbr1);
	else
		return (nbr2);
}

int		ft_abs(int x)
{
	if (x < 0)
		return (-x);
	return (x);
}
