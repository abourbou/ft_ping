/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_putnbr.c                                      .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:53:52 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:20:21 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

static void	write_nb(long nb)
{
	char buff;

	if (nb <= 9)
	{
		buff = nb + '0';
		write(1, &buff, 1);
	}
	else
	{
		write_nb(nb / 10);
		write_nb(nb % 10);
	}
}

void		ft_printf_putnbr(long nb)
{
	if (nb < 0)
		write(1, "-", 1);
	nb = (nb < 0) ? -nb : nb;
	if (nb == 0)
	{
		write(1, "0", 1);
		return ;
	}
	write_nb(nb);
}

static int	write_nb_compt(long nb, int sign)
{
	int	ret;

	ret = sign;
	if (nb < 10)
		ret++;
	else
	{
		ret += write_nb_compt(nb / 10, 0);
		ret += write_nb_compt(nb % 10, 0);
	}
	return (ret);
}

int			ft_putnbr_compt(long nb)
{
	int	sign;

	sign = 0;
	if (nb < 0)
		sign++;
	nb = (nb < 0) ? -nb : nb;
	if (nb == 0)
		return (1);
	return (write_nb_compt(nb, sign));
}
