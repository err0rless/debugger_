#include <iostream>
#include <Windows.h>
#include <stdio.h>

int main(void)
{
	DWORD count;

	while (1)
	{
		printf("Loop iteration %d\n", count);
		count++;
		Sleep(1000);
	}

	return 0;
}