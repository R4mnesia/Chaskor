#include <stdio.h>
#include <stdlib.h>

void  test_function() {
    int key = 0x55;
  char *str = "Bonjour";
  char xor[32];
    for (int i = 0; str[i]; i++) {
    xor[i] = str[i] ^ 0x45;
  }
  return ;
}

int main(void)
{
  int key = 0x55;
  char *str = "Bonjour";
  char xor[32];
  for (int i = 0; str[i]; i++) {
    xor[i] = str[i] ^ 0x55;
  }
  test_function();
  printf("%s\n", str);
  printf("%s\n", xor);
  return 1;
}

