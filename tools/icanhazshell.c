#include <stdio.h>
#include <stdlib.h>

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
