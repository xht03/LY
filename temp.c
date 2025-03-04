#include <stdio.h>

#define ALIGN_UP(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define CONGRUENT(x, a) ((x) % (a))

int main()
{
    int x;
    scanf("%d", &x);
    printf("%d\n", CONGRUENT(x, 16));
    return 0;
}