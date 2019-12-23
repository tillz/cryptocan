all: encrypter decrypter
encrypter: encrypter.c
	gcc -g -Wall -o encrypter -lcrypto -lsodium encrypter.c
decrypter: decrypter.c
	gcc -g -Wall -o decrypter -lcrypto -lsodium decrypter.c
