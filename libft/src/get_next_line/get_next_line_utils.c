/* ************************************************************************** */
/*                                                          LE - /            */
/*                                                              /             */
/*   get_next_line_utils.c                            .::    .:/ .      .::   */
/*                                                 +:+:+   +:    +:  +:+:+    */
/*   By: abourbou <abourbou@student.le-101.fr>      +:+   +:    +:    +:+     */
/*                                                 #+#   #+    #+    #+#      */
/*   Created: 2019/10/29 13:32:36 by abourbou     #+#   ##    ##    #+#       */
/*   Updated: 2020/02/03 15:51:10 by abourbou    ###    #+. /#+    ###.fr     */
/*                                                         /                  */
/*                                                        /                   */
/* ************************************************************************** */

#include "../include/get_next_line.h"

static int	ft_strcut2(char **reminder, char **line, int i)
{
	int		k;
	char	*save;

	k = 0;
	while (reminder[0][i + k + 1])
		k++;
	save = *reminder;
	save[i] = 0;
	if (!(*reminder = malloc((k + 1) * sizeof(char))))
	{
		*reminder = save;
		return (0);
	}
	while (k >= 0)
	{
		reminder[0][k] = save[i + k + 1];
		k--;
	}
	if (!(*line = ft_strjoin(save, "")))
	{
		free(save);
		return (0);
	}
	free(save);
	return (1);
}

int			ft_strcut_gnl(char **reminder, char **line)
{
	int i;

	i = 0;
	while (reminder[0][i] && reminder[0][i] != '\n')
		i++;
	if (!reminder[0][i])
	{
		*line = *reminder;
		if (!(*reminder = ft_calloc(sizeof(char), 1)))
			return (0);
		return (1);
	}
	return (ft_strcut2(reminder, line, i));
}

int			ft_lstclear_fd(t_list_fd **lst)
{
	t_list_fd *current_elem;
	t_list_fd *next_elem;

	if (!lst)
		return (-1);
	current_elem = *lst;
	while (current_elem)
	{
		next_elem = current_elem->next;
		free(current_elem->reminder);
		free(current_elem);
		current_elem = next_elem;
	}
	*lst = 0;
	return (-1);
}

int			ft_lstdelone_fd(t_list_fd **first_elem, int fd)
{
	t_list_fd	*previous;
	t_list_fd	*current;

	previous = 0;
	current = *first_elem;
	if (current->fd == fd)
	{
		*first_elem = current->next;
		free(current->reminder);
		free(current);
		return (0);
	}
	while (current->next && current->fd != fd)
	{
		previous = current;
		current = current->next;
	}
	previous->next = current->next;
	free(current->reminder);
	free(current);
	return (0);
}
