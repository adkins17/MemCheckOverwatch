#include <stdlib.h>
#include <string.h>

int main(void)
{
  char *leaked = (char *)malloc(32);
  strcpy(leaked, "this allocation is leaked");

  char *overflow = (char *)malloc(8);
  strcpy(overflow, "too long for eight bytes");
  free(overflow);

  char *double_free = (char *)malloc(16);
  free(double_free);
  free(double_free);

  return 0;
}

