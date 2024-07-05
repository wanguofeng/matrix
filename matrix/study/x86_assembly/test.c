#include <stdio.h>

int test_b (char * str)
{
	printf("str = %s\r\n", str);
	return -13;
}

int test_c(int a, int *b)
{
	int c_i = 1;

	*b = c_i + a + 10;

	int ret = test_b("enter test_b");

	return ret;
}

int main ()
{
	int main_a = 8;
	int main_b = 9;
	int main_c = test_c(main_a, &main_b);
	printf("c = %d\n", main_c);

	return 0;
};
