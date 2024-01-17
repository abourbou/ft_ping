/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_calloc.c                                      .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <marvin@le-101.fr>                +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/10/08 17:47:52 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2019/10/09 16:49:38 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include <stdlib.h>

void	*ft_calloc(size_t count, size_t size)
{
	char	*str;
	size_t	i;

	if (size * count == 0)
	{
		if ((str = malloc(1)) == 0)
			return (0);
		*str = 0;
		return (str);
	}
	if ((str = malloc(count * size)) == 0)
		return (0);
	i = 0;
	while (i < count * size)
	{
		str[i] = 0;
		i++;
	}
	return ((void *)str);
}
