//If you try this code in debug mode, it's possible that it won't work
//because some compilers(like visual studio) create jump tables to functions,
//so you wouldn't be passing the actual address of the function to Hook().
//Try release mode.
#include "MemIn.h"

int (*oAdd)(int, int);

int Add(int a, int b)
{
	return a + b;
}

int OurAdd(int a, int b)
{
	return oAdd(0xDEADBEEF, 0);
}

int main()
{
	//Returns 50
	Add(10, 40);

	//Hooks Add(), so it always returns 0xDEADBEEF
	if (!MemIn::Hook(reinterpret_cast<uintptr_t>(Add), OurAdd, reinterpret_cast<uintptr_t*>(&oAdd)))
		return 0;

	//Returns 0xDEADBEEF
	Add(10, 40);

	//Unhooks Add().
	MemIn::Unhook(reinterpret_cast<uintptr_t>(Add));

	//Returns 50
	Add(10, 40);

	return 0;
}