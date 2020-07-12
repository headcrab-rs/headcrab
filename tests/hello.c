#include <stdio.h>

char *STATICVAR = "Hello, world!\n";
char *STATICVAR2 = "Goodbye, cruel world...\n";

int main() {
  printf(STATICVAR);
  return 0;
}
