#include <stdio.h>
#include <stdlib.h>

/**
________▄▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▄______ 
_______█░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░█_____ 
_______█░▒▒▒▒▒▒▒▒▒▒▄▀▀▄▒▒▒░░█▄▀▀▄_ 
__▄▄___█░▒▒▒▒▒▒▒▒▒▒█▓▓▓▀▄▄▄▄▀▓▓▓█_ 
█▓▓█▄▄█░▒▒▒▒▒▒▒▒▒▄▀▓▓▓▓▓▓▓▓▓▓▓▓▀▄_ 
_▀▄▄▓▓█░▒▒▒▒▒▒▒▒▒█▓▓▓▄█▓▓▓▄▓▄█▓▓█_ 
_____▀▀█░▒▒▒▒▒▒▒▒▒█▓▒▒▓▄▓▓▄▓▓▄▓▒▒█ 
______▄█░░▒▒▒▒▒▒▒▒▒▀▄▓▓▀▀▀▀▀▀▀▓▄▀_ 
____▄▀▓▀█▄▄▄▄▄▄▄▄▄▄▄▄██████▀█▀▀___ 
____█▄▄▀_█▄▄▀_______█▄▄▀_▀▄▄█_____



          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
        ▄▀░░░░░░░░░░░░▄░░░░░░░▀▄ 
        █░░▄░░░░▄░░░░░░░░░░░░░░█ 
        █░░░░░░░░░░░░▄█▄▄░░▄░░░█ ▄▄▄ 
 ▄▄▄▄▄  █░░░░░░▀░░░░▀█░░▀▄░░░░░█▀▀░██
 ██▄▀██▄█░░░▄░░░░░░░██░░░░▀▀▀▀▀░░░░██
  ▀██▄▀██░░░░░░░░▀░██▀░░░░░░░░░░░░░▀██
    ▀████░▀░░░░▄░░░██░░░▄█░░░░▄░▄█░░██
       ▀█░░░░▄░░░░░██░░░░▄░░░▄░░▄░░░██
       ▄█▄░░░░░░░░░░░▀▄░░▀▀▀▀▀▀▀▀░░▄▀
      █▀▀█████████▀▀▀▀████████████▀
      ████▀  ███▀      ▀███  ▀██▀
      
**/

int main(void)
{
    printf("Before elevation:\n");
    system("/bin/sh -c /usr/bin/id");
    printf("\nAfter elevation:\n");
    system("/bin/sh -c /usr/bin/id");

    printf("\nHere, have a shell.\n");
    system("/bin/sh");
    return 0;
}
