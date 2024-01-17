# **************************************************************************** #
#                                                                              #
#                                                         :::      ::::::::    #
#    Makefile                                           :+:      :+:    :+:    #
#                                                     +:+ +:+         +:+      #
#    By: abourbou <abourbou@student.42lyon.fr>      +#+  +:+       +#+         #
#                                                 +#+#+#+#+#+   +#+            #
#    Created: 2019/10/11 11:01:57 by abourbou          #+#    #+#              #
#    Updated: 2024/01/17 23:11:17 by abourbou         ###   ########lyon.fr    #
#                                                                              #
# **************************************************************************** #


#VARIABLE

NAME		=	libft
CC			=	gcc
FLAGS		=	-Wall -Werror -Wextra
HEADER		=	-I$(PATH_INC)

# Color Code and template code
GREY = \033[2:49;39m
RED = \033[1;31m
GREEN = \033[3;32m
YELLOW = \033[3;49;33m
BLUE = \033[3;4;34m
BLUEE = \033[3;34m
PURPLE = \033[3;35m
CYAN = \033[3;36m
RESET = \033[0m
ICONOK = \033[1;32m
ICONKO = \033[1;31m
CO_DELET = \033[3;31m
CO_A_OUT = \033[96m
WHITE = \033[1;37m

# Path directories
PATH_INC	=	include
PATH_SRC	=	src
PATH_OBJ	=	obj

# Source
LIBFT_PATH	=	lib_common
SRC_LIBFT	= 	ft_atoi.c  ft_strdup.c ft_bzero.c \
				ft_strjoin.c ft_calloc.c ft_strlcat.c ft_isalnum.c \
	 			ft_memccpy.c ft_strlcpy.c ft_isalpha.c ft_memchr.c \
				ft_strlen.c ft_isascii.c ft_memcmp.c ft_strmapi.c \
				ft_isdigit.c ft_memcpy.c ft_strncmp.c ft_isprint.c \
				ft_strcmp.c \
	 			ft_memmove.c ft_strnstr.c ft_itoa.c ft_memset.c \
				ft_strrchr.c  ft_putchar_fd.c ft_strtrim.c  ft_putendl_fd.c \
				ft_substr.c  ft_putnbr_fd.c ft_tolower.c  ft_putstr_fd.c \
				ft_toupper.c  ft_split.c ft_strchr.c \
				ft_lstmap_bonus.c ft_lstnew_bonus.c ft_lstsize_bonus.c \
				ft_lstadd_back_bonus.c ft_lstadd_front_bonus.c \
				ft_lstclear_bonus.c ft_lstdelone_bonus.c ft_lstiter_bonus.c \
				ft_lstlast_bonus.c

GNL_PATH	=	get_next_line
SRC_GNL		=	get_next_line.c get_next_line_utils.c

PRINTF_PATH	=	ft_printf
SRC_PRINTF	=	ft_csp.c ft_cut.c \
				ft_hex_maj_putnbr.c ft_hex_min_putnbr.c \
				ft_math_tools.c ft_printf.c \
				ft_putnbr.c ft_tools.c \
				ft_uns_putnbr.c ft_write.c \
				ft_write_number.c ft_int_bis.c

SRC 		=	$(addprefix $(PATH_SRC)/, \
				$(addprefix $(GNL_PATH)/,$(SRC_GNL)) \
				$(addprefix $(LIBFT_PATH)/,$(SRC_LIBFT)) \
				$(addprefix $(PRINTF_PATH)/,$(SRC_PRINTF)))

OBJ			=	$(addprefix $(PATH_OBJ)/, $(SRC:.c=.o))

# Headers
INCL_FILES 	=	libft.h get_next_line.h ft_printf.h libft_core.h

INC			=	$(addprefix include/,$(INCL_FILES))

# Rules
all			:	$(NAME)

$(NAME)	:	$(OBJ) $(INC)
	@ ar rcs $(NAME).a $(OBJ)
	@ printf "\033[2K\r$(BLUE)$(NAME)$(RESET)$(BLUEE): $(ICONOK)library compiled [√]$(RESET)\n"

$(PATH_OBJ)/%.o		: 	%.c    $(INC)
	@ mkdir -p $(dir $@)
	@ printf "\033[2K\r$(PURPLE)$<: $(CYAN)loading..$(RESET)"
	@ $(CC) $(FLAGS) $(HEADER) -c  -o $@ $<

clean	:
	@ rm -rf $(OBJ)
	@ rm -rf obj

fclean	:	clean
	@ rm -rf $(NAME).a
	@ printf "$(CYAN)'$(NAME).a'$(RESET) and all .o has been $(RED)deleted. 🗑️\n$(RESET)"

re		:	fclean all

.PHONY: all compil clean fclean re