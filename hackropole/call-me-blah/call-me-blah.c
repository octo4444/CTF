#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int
main(void)
{
	void (*call_me)(char *);
	char blah[32];

	printf("%p\n", stdin);  // affiche l'adresse en hexa(leak)

	if (scanf("%zd%*c", (ssize_t *)&call_me) != 1) { // d=entiersigné %*c=ignore le \n     ssize_t permet de dire que callme est une variable d'entier signé or c'est pour sotcker une adresse ?
		fputs("This is not a number.\n", stderr);
		return EXIT_FAILURE;
	}

	if (fgets(blah, sizeof(blah), stdin) == NULL) {
		fputs("Read error.\n", stderr);
		return EXIT_FAILURE;
	}

    call_me(blah);

	return EXIT_SUCCESS;
}
