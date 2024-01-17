/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_write.c                                       .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/08 10:45:54 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:23:55 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

int	ft_perc(t_format *elem, int val_nbr)
{
	int				val_flag;

	val_nbr = 1;
	val_flag = ft_max(elem->n_flag, val_nbr);
	if (elem->flag == '0' || !(elem->flag))
	{
		elem->flag = !(elem->flag) ? ' ' : '0';
		ft_printchar(elem->flag, val_flag - val_nbr);
		write(1, "%", 1);
	}
	else
	{
		write(1, "%", 1);
		ft_printchar(' ', val_flag - val_nbr);
	}
	return (val_flag);
}

int	ft_csp(t_format *elem)
{
	if (elem->specif == 'c')
		return (ft_printf_char(elem));
	else if (elem->specif == 's')
		return (ft_printf_string(elem, 0));
	else if (elem->specif == 'p')
		return (ft_printf_pointer(elem, 14));
	return (-1);
}

int	ft_write_number(t_format *elem)
{
	va_list	aq;

	va_copy(aq, elem->cpy_arg);
	if (elem->prec && elem->n_prec == 0 && !va_arg(aq, int))
	{
		ft_printchar(' ', elem->n_flag);
		va_end(aq);
		return (elem->n_flag);
	}
	va_end(aq);
	if (elem->specif == 'd' || elem->specif == 'i')
		return (ft_printf_int(elem, 0, 0));
	else if (elem->specif == 'u')
		return (ft_printf_uns_int(elem, 0, 0));
	else if (elem->specif == 'x')
		return (ft_printf_hex_min(elem, 0, 0));
	else if (elem->specif == 'X')
		return (ft_printf_hex_maj(elem, 0, 0));
	return (-1);
}

int	ft_printf_write(t_format *elem)
{
	if (elem->specif == '%')
		return (ft_perc(elem, 0));
	else if (elem->specif == 'c' || elem->specif == 's'
			|| elem->specif == 'p')
		return (ft_csp(elem));
	else
		return (ft_write_number(elem));
	return (-1);
}
