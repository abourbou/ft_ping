/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_csp.c                                           :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abourbou <abourbou@student.42lyon.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/12 16:43:31 by abourbou          #+#    #+#             */
/*   Updated: 2024/01/17 21:59:40 by abourbou         ###   ########lyon.fr   */
/*                                                                            */
/* ************************************************************************** */


#include "../include/ft_printf.h"

static int	write_address_compt(void *pointer)
{
	int		i;
	int		hex;
	long	adr;
	int		compt;

	adr = (long)pointer;
	compt = 16;
	if (adr == 0)
		return (1);
	i = 8 * sizeof(void *) - 4;
	while (i >= 0)
	{
		hex = adr >> i & 0xf;
		i -= 4;
		if (hex)
			return (compt);
		compt--;
	}
	return (0);
}

int			ft_printf_char(t_format *elem)
{
	char	c;
	int		n;

	n = elem->n_flag - 1;
	c = va_arg(elem->cpy_arg, int);
	if (elem->flag == '-')
	{
		write(1, &c, 1);
		ft_printchar(' ', n);
	}
	else
	{
		ft_printchar(' ', n);
		write(1, &c, 1);
	}
	return (ft_max(n + 1, 1));
}

int			ft_printf_string(t_format *elem, int alloc)
{
	int		min;
	char	*str;

	str = va_arg(elem->cpy_arg, char *);
	if (!str)
	{
		if (!(str = ft_strdup("(null)")))
			return (-1);
		alloc = 1;
	}
	min = (elem->prec) ? ft_min(ft_strlen(str), elem->n_prec) :
		(int)ft_strlen(str);
	if (elem->flag == '-')
	{
		write(1, str, min);
		ft_printchar(' ', elem->n_flag - min);
	}
	else
	{
		ft_printchar(' ', elem->n_flag - min);
		write(1, str, min);
	}
	if (alloc)
		free(str);
	return (ft_max(min, elem->n_flag));
}

int			ft_printf_pointer(t_format *elem, int len)
{
	void	*pointer;
	int		n;

	pointer = va_arg(elem->cpy_arg, void *);
	len = 2 + write_address_compt(pointer);
	if (elem->prec == '.' && !(elem->n_prec) && !pointer)
		len--;
	n = elem->n_flag - len;
	if (elem->flag == '-')
	{
		write(1, "0x", 2);
		if (!(elem->prec == '.' && !(elem->n_prec) && !pointer))
			write_address(pointer);
		ft_printchar(' ', n);
	}
	else
	{
		ft_printchar(' ', n);
		write(1, "0x", 2);
		if (!(elem->prec == '.' && !(elem->n_prec) && !pointer))
			write_address(pointer);
	}
	return (ft_max(len, n + len));
}
