default:
	gcc example.c -o example -lsodium -Wall -Wextra -Werror -pedantic -O3
	gcc test.c -o test -lsodium -Wall -Wextra -Werror -pedantic -O3
