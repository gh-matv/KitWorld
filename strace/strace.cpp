
#include <iostream>
#include <sstream>
#include <vector>

#include "tracer.hpp"


int main()
{   	
	TRACE(MessageBoxA);
	TRACE(Beep);

	MessageBoxA(NULL, "A", "B", NULL);
	Beep(1000, 100);
}
