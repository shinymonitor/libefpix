default:
	gcc src/example.c lib/monocypher.c lib/monocypher-ed25519.c -o build/example -Wall -Wextra -Werror -pedantic -O3
	gcc test.c lib/monocypher.c lib/monocypher-ed25519.c -o build/test -Wall -Wextra -Werror -pedantic -O3