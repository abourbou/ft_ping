/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_int_bis.c                                     .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/11/12 12:53:17 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:59:18 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/ft_printf.h"

void	int_case_first(int val_flag, int val_prec, int sign, unsigned int u_nbr)
{
	ft_printchar(' ', val_flag);
	write(1, "-", sign);
	ft_printchar('0', val_prec);
	ft_uns_putnbr(u_nbr);
}

void	int_case_second(int val_flag, int val_prec, int sign,
											unsigned int u_nbr)
{
	write(1, "-", sign);
	ft_printchar('0', val_prec);
	ft_uns_putnbr(u_nbr);
	ft_printchar(' ', val_flag);
}

void	int_case_third(int val_flag, int sign, unsigned int u_nbr)
{
	write(1, "-", sign);
	ft_printchar('0', val_flag);
	ft_uns_putnbr(u_nbr);
}

void	int_case_forth(int val_flag, int nbr)
{
	ft_printchar(' ', val_flag);
	ft_printf_putnbr(nbr);
}
