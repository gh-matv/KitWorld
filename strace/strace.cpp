
#include <Windows.h>

#include <iostream>
#include <vector>
#include <string>
#include <memory>

#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>

PLH::CapstoneDisassembler dis(PLH::Mode::x86);
std::vector<std::shared_ptr<PLH::x86Detour>> detours;

void logger_fx(std::string fxname)
{
	std::cout << (std::string("Called ") + fxname) << std::endl;
}

__declspec(naked) void fx()
{
	const char* function_name;
	const void* logger_address;

	function_name = "";
	
	logger_fx(function_name);

	__asm nop
	__asm push 0
	__asm ret
}

void setlog(void* function_to_hook, const char *fxname = "", const char* fxdetails = "")
{
	
	union splitter_t { void* ptr; struct { char a, b, c, d; }; } ;
	static const splitter_t funcnameaddr = { (void*)fxname };
	static const splitter_t logaddr = { (void*)&logger_fx };

	// definition of the function
	const char func[] = {
	0x68, funcnameaddr.a, funcnameaddr.b, funcnameaddr.c, funcnameaddr.d, // push the fx name
	0x9A, logaddr.a, logaddr.b, logaddr.c, logaddr.d, 0, 0,		// call the logger function									   
	0x68, 0,0,0,0, 		// push the return address
	0xC3				// ret
	};

	// Allocate memory for the function and make it executable
	DWORD oldProtect;
	char *newfx = (char*)malloc(sizeof(func));
	auto vpres = VirtualProtect(newfx, sizeof(newfx), PAGE_EXECUTE_READWRITE, &oldProtect);
	auto err = GetLastError();

	// Copy the content of the fx
	memcpy(newfx, func, sizeof(func));

	// Hook the function into the newly created one
	uint64_t original;
	uint64_t newfx64 = 0 | reinterpret_cast<intptr_t>(newfx); // Fix to have the new function address as 64b padded with zeroes
	detours.push_back(std::make_shared<PLH::x86Detour>(
		(const uint64_t)function_to_hook,
		(const uint64_t)newfx64,
		(uint64_t*)&original,
		dis
	));
	detours.back()->hook();

	// Update the pointers in the function
	// *reinterpret_cast<char*>(newfx + 1) = (intptr_t)&logger;
	*reinterpret_cast<char*>(newfx + 13) = (intptr_t)original;
}

int main()
{   			
	setlog(&MessageBoxA, "MessageBoxA");
	setlog(&Beep);
	Beep(1000, 10);
}
