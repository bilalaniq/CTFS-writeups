CHALLENGE=ch12
USER=app-systeme-$(CHALLENGE)
USER_CRACKED=$(USER)-cracked

CC=gcc
CFLAGS=-m32 -Wall -no-pie -fno-stack-protector
LDFLAGS=

SRC=$(CHALLENGE).c
OBJ=$(SRC:.c=.o)
BIN=$(CHALLENGE)

.DEFAULT_GOAL := challenge
.PHONY : clean all

$(BIN): $(OBJ)
	@echo "Compiling..."
	$(CC) -o $@ $(SRC) $(LDFLAGS) $(CFLAGS)

challenge: $(BIN)
	@echo "Applying permissions..."
	rm -f $(OBJ)
	chown $(USER_CRACKED):$(USER) $(BIN) .passwd Makefile $(SRC)
	chmod 400 .passwd
	chmod 440 $(SRC) Makefile
	chmod 550 $(BIN)
	chmod u+s $(BIN)

