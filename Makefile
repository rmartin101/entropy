all: entropy

entropy: entropy.c
	gcc -o entropy -g -O4 entropy.c -lm 

.PHONEY: clean run

run:
	./entropy -f test_data/foxn3.dat

clean:
	rm -f entropy *.o 
