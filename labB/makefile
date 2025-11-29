CC := gcc
CFLAGS := -g -O0 -Wall -Wextra -std=c11 -m32
TARGETS := bubblesort hexaPrint AntiVirus

all: $(TARGETS)

bubblesort: Bubblesort.c
	$(CC) $(CFLAGS) -o $@ $^

hexaPrint: hexaPrint.c
	$(CC) $(CFLAGS) -o $@ $^

AntiVirus: AntiVirus.c
	$(CC) $(CFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f $(TARGETS) *.o
