/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf.h                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: abourbou <abourbou@student.42lyon.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2019/11/12 12:59:54 by abourbou          #+#    #+#             */
/*   Updated: 2024/01/17 22:49:55 by abourbou         ###   ########lyon.fr   */
/*                                                                            */
/* ************************************************************************** */


#ifndef FT_PRINTF_H
# define FT_PRINTF_H

# include <stdarg.h>
# include <unistd.h>
# include <stdio.h>
# include <stdlib.h>
# include <unistd.h>
# include "libft_core.h"

typedef struct	s_format
{
	char		flag;
	int			n_flag;
	char		prec;
	int			n_prec;
	char		specif;
	va_list		cpy_arg;
}				t_format;

/*
** FT_PRINTF
*/
int				ft_printf(const char *str,
		...) __attribute__((format(printf,1,2)));

/*
** TOOLS
*/
int				ft_printf_atoi(const char *str);
int				ft_is_specifier(char str);
void			ft_printchar(char c, int n);
void			write_address(void *pointer);

/*
** FT_PUTNBR
*/
void			ft_printf_putnbr(long nb);
int				ft_putnbr_compt(long nb);

/*
** FT_UNS_PUTNBR
*/
void			ft_uns_putnbr(unsigned int nb);
int				ft_uns_putnbr_compt(unsigned int nb);

/*
**FT_HEX_MIN_PUTNBR
*/
int				ft_hex_min_putnbr_compt(unsigned int nb);
void			ft_hex_min_putnbr(unsigned int nb);

/*
**FT_HEX_MAJ_PUTNBR
*/
int				ft_hex_maj_putnbr_compt(unsigned int nb);
void			ft_hex_maj_putnbr(unsigned int nb);

/*
**MATH_TOOLS
*/
int				ft_min(int nbr1, int nbr2);
int				ft_max(int nbr1, int nbr2);
int				ft_abs(int x);

/*
**FT_CUT
*/
int				ft_flag(const char *str, t_format *elem);
int				ft_nflag(va_list *ap, const char *str, t_format *elem, int i);
int				ft_precision(va_list *ap,
		const char *str, t_format *buffer, int i);
int				ft_specifier(va_list *ap,
		const char *str, t_format *elem, int i);

/*
**FT_WRITE
*/
int				ft_printf_write(t_format *elem);

/*
**FT_CSP
*/
int				ft_printf_char(t_format *elem);
int				ft_printf_string(t_format *elem, int alloc);
int				ft_printf_pointer(t_format *elem, int len);

/*
**FT_WRITE_NUMBER
*/
int				ft_printf_int(t_format *elem, int val_nbr, int val_prec);
int				ft_printf_uns_int(t_format *elem, int val_nbr, int val_prec);
int				ft_printf_hex_min(t_format *elem, int val_nbr, int val_prec);
int				ft_printf_hex_maj(t_format *elem, int val_nbr, int val_prec);

/*
**FT_INT_BIS
*/
void			int_case_first(int val_flag, int val_prec,
		int sign, unsigned int u_nbr);
void			int_case_second(int val_flag, int val_prec,
		int sign, unsigned int u_nbr);
void			int_case_third(int val_flag, int sign, unsigned int u_nbr);
void			int_case_forth(int val_flag, int nbr);

#endif
