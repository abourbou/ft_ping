/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_printf.c                                      .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:53:37 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:21:04 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

t_format	*ft_cut(va_list *ap, const char *str)
{
	int			i;
	int			interrupt;
	t_format	*elem;

	interrupt = 1;
	if (!(elem = malloc(sizeof(t_format))))
		interrupt = 0;
	i = ft_flag(str, elem);
	if ((i = ft_nflag(ap, str, elem, i)) == -1)
		interrupt = 0;
	if ((i = ft_precision(ap, str, elem, i)) == -1)
		interrupt = 0;
	if ((ft_specifier(ap, str, elem, i) == -1))
	{
		interrupt = 0;
		va_end(elem->cpy_arg);
	}
	if (interrupt == 0)
	{
		free(elem);
		elem = 0;
	}
	return (elem);
}

int			ft_format(const char *str, va_list *ap, int i, int *val_ret)
{
	t_format	*elem;
	int			verif;

	i++;
	if (!(elem = ft_cut(ap, str + i)))
		return (-1);
	if ((verif = ft_printf_write(elem)) == -1)
	{
		va_end(elem->cpy_arg);
		free(elem);
		return (-1);
	}
	*val_ret += verif;
	while (str[i] && !ft_is_specifier(str[i]))
		i++;
	if (str[i])
		i++;
	va_end(elem->cpy_arg);
	free(elem);
	return (i);
}

int			ft_printf(const char *str, ...)
{
	int		i;
	int		compt;
	int		val_ret;
	va_list	ap;

	if (!str)
		return (-1);
	i = 0;
	val_ret = 0;
	va_start(ap, str);
	while (str[i])
	{
		compt = 0;
		while (str[i + compt] && str[i + compt] != '%')
			compt++;
		write(1, str + i, compt);
		val_ret += compt;
		i += compt;
		if (str[i])
			if ((i = ft_format(str, &ap, i, &val_ret)) == -1)
				return (-1);
	}
	va_end(ap);
	return (val_ret);
}
