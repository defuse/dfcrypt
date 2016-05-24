main: main.c dfcrypt.h dfcrypt.o
	gcc main.c dfcrypt.o -o main -lsodium

dfcrypt.o: dfcrypt.c dfcrypt.h
	gcc -c dfcrypt.c -o dfcrypt.o

.PHONY: clean
clean:
	rm -f dfcrypt.o main
