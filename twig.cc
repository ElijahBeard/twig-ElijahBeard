#include <cstdlib>
#include <iostream>

int debug = 0;
int mask = 0;
int help = 0;

int main(int argc, char *argv[]) {
	if (strcmp(argv[1],"-d") == 0) { debug = 1; }
	if (strcmp(argv[1], "-i") == 0) { mask = 1; }
    if (strcmp(argv[1], "-h") == 0) { help = 1; }

    return 0;
}