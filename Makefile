all:
	gcc -W aes.c sha256.c client.c -o client -lgmp -lm
clean:
	rm client
