all: entropy

entropy: entropy.c
	gcc -o entropy -g -O4 entropy.c -lm 

.PHONEY: clean

clean:
	rm -f emtropy *.o 
