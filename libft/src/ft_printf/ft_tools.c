/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_tools.c                                       .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 16:42:42 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:56:54 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

int		ft_is_specifier(char str)
{
	if (str == 'c' || str == 's' || str == 'p'
			|| str == 'd' || str == 'i' || str == 'u'
			|| str == 'x' || str == 'X' || str == '%')
		return (1);
	return (0);
}

void	ft_printchar(char c, int n)
{
	int		i;
	char	buffer[10000];

	i = 0;
	if (n <= 0)
		return ;
	while (i < 10000)
	{
		buffer[i] = c;
		i++;
	}
	while (n > 10000)
	{
		write(1, buffer, 10000);
		n = n - 10000;
	}
	write(1, buffer, n);
}

int		ft_printf_atoi(const char *str)
{
	int	i;
	int	sign;
	int	nb;

	i = 0;
	sign = 1;
	nb = 0;
	if (str[i] == '+' || str[i] == '-')
	{
		if (str[i] == '-')
			sign *= -1;
		i++;
	}
	if (str[i] < '0' || str[i] > '9')
		return (0);
	while (str[i] >= '0' && str[i] <= '9')
	{
		nb = nb * 10 + str[i] - '0';
		i++;
	}
	return (sign * nb);
}

void	write_address(void *pointer)
{
	int		i;
	int		hex;
	long	adr;
	char	printable;
	int		beginning;

	adr = (long)pointer;
	beginning = 0;
	if (adr == 0)
	{
		write(1, "0", 1);
		return ;
	}
	i = 8 * sizeof(void *) - 4;
	while (i >= 0)
	{
		hex = adr >> i & 0xf;
		printable = (hex >= 10) ? hex - 10 + 'a' : hex + '0';
		beginning += (printable != '0') ? 1 : 0;
		if (beginning)
			write(1, &printable, 1);
		i -= 4;
	}
}
