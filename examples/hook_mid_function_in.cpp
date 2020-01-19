//If you try this code in debug mode, it's possible that it won't work
//because some compilers(like visual studio) create jump tables to functions,
//so you wouldn't be passing the actual address of the function to Hook().
//Try release mode.
#include "MemIn.h"

float globalFloat = 0.0f;

//Does something
float Function(float a, float b)
{
	globalFloat += 1.0f;

	float x = a + b * 2;

	b = (x * 2) + (a / 2.0f);

	return (a + b + x) * globalFloat;
}

//Set globalFloat to zero making Function always return 0
void OurFunction()
{
	globalFloat = 0;
}

int main()
{
	//Returns 70.5f
	Function(5.0f, 8.0f);

	//Performs a mid function hook on Function(). saveCpuStateMask saves the CPU state before calling OurFunction.
	//You don't have to use trampoline.
	//30 is an offset to specify an address in the middle of Function().
	if (!MemIn::Hook(reinterpret_cast<uintptr_t>(Function) + 30, OurFunction, nullptr, GPR | FLAGS | XMMX))
		return 0;

	//Returns 0.0f
	Function(5.0f, 8.0f);

	//Unhooks Add().
	MemIn::Unhook(reinterpret_cast<uintptr_t>(Function) + 30);

	//Returns 70.5f
	Function(5.0f, 8.0f);

	return 0;
}