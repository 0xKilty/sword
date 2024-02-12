CC=gcc

CCFLAGS=-Wall -O3

LIBRARIES=-lcapstone

sword: sword.o elf_stuff.o
	$(CC) $(CCFLAGS) $^ $(LIBRARIES) -o $@

sword.o: sword.c elf_stuff.h
	$(CC) $(CCFLAGS) -c $<

elf_stuff.o: elf_stuff.c elf_stuff.h
	$(CC) $(CCFLAGS) -c $<

clean:
	-rm -f sword *.o
