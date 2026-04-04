default:
	gcc src/example.c -o build/example -lsodium -Wall -Wextra -Werror -pedantic -O3
	gcc test.c -o build/test -lsodium -Wall -Wextra -Werror -pedantic -O3