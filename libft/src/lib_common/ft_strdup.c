/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   ft_strdup.c                                      .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <marvin@le-101.fr>                +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/10/09 09:23:25 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2019/10/09 09:32:56 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include <stdlib.h>

char	*ft_strdup(const char *s1)
{
	int		i;
	int		j;
	char	*strcpy;

	i = 0;
	while (s1[i])
		i++;
	if ((strcpy = malloc((i + 1) * sizeof(char))) == 0)
		return (0);
	j = 0;
	while (j <= i)
	{
		strcpy[j] = s1[j];
		j++;
	}
	return (strcpy);
}
