all:
	gcc dannycrypt.c -g -Wall -Wpedantic -o dannycrypt
png:
	gcc dannycrypt.c -g -Wall -Wpedantic -o dannycrypt -lpng -DTUX_PNG
