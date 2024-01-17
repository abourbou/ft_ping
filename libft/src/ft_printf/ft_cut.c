/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_cut.c                                         .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:52:40 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:20:13 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

int			ft_flag(const char *str, t_format *elem)
{
	int		i;
	char	c;

	i = 0;
	c = str[i];
	if (str[i] == '0' || str[i] == '-')
	{
		elem->flag = str[i];
		while (str[i] == c)
			i++;
	}
	else
		elem->flag = 0;
	return (i);
}

int			ft_nflag(va_list *ap, const char *str, t_format *elem, int i)
{
	if (str[i] == '.' || ft_is_specifier(str[i]))
		elem->n_flag = 0;
	else if (str[i] == '*')
	{
		elem->n_flag = va_arg(*ap, int);
		i++;
		if (elem->n_flag < 0)
			elem->flag = '-';
		elem->n_flag = ft_abs(elem->n_flag);
	}
	else if (str[i] >= '0' && str[i] <= '9')
	{
		elem->n_flag = ft_atoi(str + i);
		while (str[i] >= '0' && str[i] <= '9')
			i++;
	}
	else
		return (-1);
	return (i);
}

static int	ft_nprecision(va_list *ap, const char *str, t_format *buffer, int i)
{
	if (str[i] == '*')
	{
		buffer->n_prec = va_arg(*ap, int);
		if (buffer->n_prec < 0)
		{
			buffer->prec = 0;
			buffer->n_prec = 0;
		}
		i++;
	}
	else if (str[i] >= '0' && str[i] <= '9')
	{
		buffer->n_prec = ft_atoi((str + i));
		while (str[i] >= '0' && str[i] <= '9')
			i++;
	}
	else if (ft_is_specifier(str[i]))
		buffer->n_prec = 0;
	else
		return (-1);
	return (i);
}

int			ft_precision(va_list *ap, const char *str, t_format *buffer, int i)
{
	if (str[i] == '.')
	{
		buffer->prec = '.';
		i++;
		if ((i = ft_nprecision(ap, str, buffer, i)) == -1)
			return (-1);
	}
	else if (ft_is_specifier(str[i]))
	{
		buffer->prec = 0;
		buffer->n_prec = 0;
	}
	else
		return (-1);
	return (i);
}

int			ft_specifier(va_list *ap, const char *str, t_format *elem, int i)
{
	int		buff_int;

	if (ft_is_specifier(str[i]))
	{
		elem->specif = str[i];
		va_copy(elem->cpy_arg, *ap);
		if (str[i] != '%')
			buff_int = va_arg(*ap, int);
	}
	else
		return (-1);
	(void)buff_int;
	return (1);
}
