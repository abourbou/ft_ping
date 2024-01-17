/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_write_number.c                                .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:59:47 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:24:28 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

int	ft_printf_int(t_format *elem, int val_nbr, int val_prec)
{
	int				nbr;
	int				val_flag;
	int				sign;
	unsigned int	u_nbr;

	nbr = va_arg(elem->cpy_arg, int);
	sign = (nbr < 0) ? 1 : 0;
	u_nbr = nbr * (1 - 2 * sign);
	val_nbr = ft_putnbr_compt(nbr);
	val_prec = ft_max(0, elem->n_prec - (val_nbr - sign));
	val_flag = ft_max(0, elem->n_flag - (val_prec + val_nbr));
	if ((elem->flag == '0' || !elem->flag) && elem->prec)
		int_case_first(val_flag, val_prec, sign, u_nbr);
	else if (elem->flag == '-')
		int_case_second(val_flag, val_prec, sign, u_nbr);
	else if (elem->flag == '0')
		int_case_third(val_flag, sign, u_nbr);
	else
		int_case_forth(val_flag, nbr);
	return (val_flag + val_prec + val_nbr);
}

int	ft_printf_uns_int(t_format *elem, int val_nbr, int val_prec)
{
	unsigned int	nbr;
	int				val_flag;

	nbr = va_arg(elem->cpy_arg, int);
	val_nbr = ft_uns_putnbr_compt(nbr);
	val_prec = ft_max(elem->n_prec, val_nbr);
	val_flag = ft_max(elem->n_flag, val_prec);
	if ((elem->flag == '0' || !elem->flag) && elem->prec)
	{
		ft_printchar(' ', val_flag - val_prec);
		ft_printchar('0', val_prec - val_nbr);
		ft_uns_putnbr(nbr);
		return (val_flag);
	}
	else if (elem->flag == '-')
	{
		ft_printchar('0', val_prec - val_nbr);
		ft_uns_putnbr((long)nbr);
		ft_printchar(' ', val_flag - val_prec);
		return (val_flag);
	}
	ft_printchar((elem->flag == '0') ? '0' : ' ', val_flag - val_nbr);
	ft_uns_putnbr(nbr);
	return (val_flag);
}

int	ft_printf_hex_min(t_format *elem, int val_nbr, int val_prec)
{
	unsigned int	nbr;
	int				val_flag;

	nbr = va_arg(elem->cpy_arg, int);
	val_nbr = ft_hex_min_putnbr_compt(nbr);
	val_prec = ft_max(elem->n_prec, val_nbr);
	val_flag = ft_max(elem->n_flag, val_prec);
	if ((elem->flag == '0' || !elem->flag) && elem->prec)
	{
		ft_printchar(' ', val_flag - val_prec);
		ft_printchar('0', val_prec - val_nbr);
		ft_hex_min_putnbr(nbr);
		return (val_flag);
	}
	else if (elem->flag == '-')
	{
		ft_printchar('0', val_prec - val_nbr);
		ft_hex_min_putnbr(nbr);
		ft_printchar(' ', val_flag - val_prec);
		return (val_flag);
	}
	ft_printchar((elem->flag == '0') ? '0' : ' ', val_flag - val_nbr);
	ft_hex_min_putnbr(nbr);
	return (val_flag);
}

int	ft_printf_hex_maj(t_format *elem, int val_nbr, int val_prec)
{
	unsigned int	nbr;
	int				val_flag;

	nbr = va_arg(elem->cpy_arg, int);
	val_nbr = ft_hex_maj_putnbr_compt(nbr);
	val_prec = ft_max(elem->n_prec, val_nbr);
	val_flag = ft_max(elem->n_flag, val_prec);
	if ((elem->flag == '0' || !elem->flag) && elem->prec)
	{
		ft_printchar(' ', val_flag - val_prec);
		ft_printchar('0', val_prec - val_nbr);
		ft_hex_maj_putnbr(nbr);
		return (val_flag);
	}
	else if (elem->flag == '-')
	{
		ft_printchar('0', val_prec - val_nbr);
		ft_hex_maj_putnbr(nbr);
		ft_printchar(' ', val_flag - val_prec);
		return (val_flag);
	}
	ft_printchar((elem->flag == '0') ? '0' : ' ', val_flag - val_nbr);
	ft_hex_maj_putnbr(nbr);
	return (val_flag);
}
