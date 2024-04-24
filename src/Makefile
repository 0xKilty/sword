CC=gcc
CCFLAGS=-Wall -O3
LIBRARIES=-lcapstone -lm

sword: sword.o elf_stuff.o entropy.o user_interaction.o
	$(CC) $(CCFLAGS) $^ $(LIBRARIES) -o $@

sword.o: sword.c elf_stuff.h entropy.h user_interaction.h
	$(CC) $(CCFLAGS) -c $<

elf_stuff.o: elf_stuff.c elf_stuff.h
	$(CC) $(CCFLAGS) -c $<

entropy.o: entropy.c entropy.h
	$(CC) $(CCFLAGS) -c $<

user_interaction.o: user_interaction.c user_interaction.h
	$(CC) $(CCFLAGS) -c $<

clean:
	-rm -f sword *.o
