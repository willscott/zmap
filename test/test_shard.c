#include <stdio.h>
#include <check.h>

#include "iterator.h"

int main() {
	printf("%s\n", "Hello world!");
	iterator_t *it = iterator_init(1, 0, 1);
	printf("%u\n", iterator_get_sent(it));
	return 0;
}
