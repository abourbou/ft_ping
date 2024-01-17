/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_hex_min_putnbr.c                              .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:52:55 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:20:16 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

static void		write_nb(unsigned int nb)
{
	char buff;

	if (nb <= 15)
	{
		buff = (nb > 9) ? nb - 10 + 'a' : nb + '0';
		write(1, &buff, 1);
	}
	else
	{
		write_nb(nb / 16);
		write_nb(nb % 16);
	}
}

void			ft_hex_min_putnbr(unsigned int nb)
{
	if (nb == 0)
	{
		write(1, "0", 1);
		return ;
	}
	write_nb(nb);
}

static int		write_nb_compt(unsigned int nb)
{
	int	ret;

	ret = 0;
	if (nb <= 15)
		ret++;
	else
	{
		ret += write_nb_compt(nb / 16);
		ret += write_nb_compt(nb % 16);
	}
	return (ret);
}

int				ft_hex_min_putnbr_compt(unsigned int nb)
{
	if (nb == 0)
		return (1);
	return (write_nb_compt(nb));
}
