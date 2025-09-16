default:
	gcc example.c lib/monocypher.c lib/monocypher-ed25519.c -o example -Wall -Wextra -Werror -pedantic -O3