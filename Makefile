.RECIPEPREFIX := >
CC=gcc
CFLAGS=-std=c11 -Wall -Wextra -pedantic -g
LDFLAGS=-lpcap

SRC=src/main.c src/rules.c src/session.c
OBJ=$(SRC:.c=.o)

firewall: $(OBJ)
>$(CC) $(CFLAGS) -o $@ $(OBJ) $(LDFLAGS)

clean:
>rm -f firewall $(OBJ)

.PHONY: clean
