
#include <Windows.h>

#include <iostream>
#include <vector>
#include <string>
#include <memory>

#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>

PLH::CapstoneDisassembler dis(PLH::Mode::x86);
std::vector<std::shared_ptr<PLH::x86Detour>> detours;

#define H(fx) (setlog(&fx, #fx, #fx))

 void __cdecl logger_fx(const char* fxname) noexcept
{
	std::cout << (std::string("Called ") + fxname) << std::endl;
}

//#pragma const_seg(".t_const")
#pragma optimize("", off)
__declspec(naked) void fx() noexcept
{
	// OFFSET = 0
	// 00A91350 B9 A0 0F 00 00       mov         ecx,0FA0h				<- to fix with the correct ptr to the function name
	// 00A91355 E8 56 FE FF FF       call        logger_fx(0A911B0h)	<- to fix with the correct relative ptr to logger_fx
	// Address offset = 6
	logger_fx((const char*)0x42424242);

	__asm nop
	__asm push 0x12345677											//	<- to fix with the correct pointer to the original function
	__asm ret
}
__declspec(naked) void fxend() {}
#pragma optimize("", on)
//#pragma const_seg()

void setlog(void* function_to_hook, const char *fxname = "", const char* fxdetails = "")
{

	// Allocate memory for the function and make it executable
	DWORD oldProtect;
	auto newfxsz = (int)&fxend - (int)&fx;
	char *newfx = (char*)malloc(newfxsz);

	if (!newfx)
	{
		throw std::runtime_error("Unable to allocate memory for the hook !");
	}

	if (!VirtualProtect(newfx, newfxsz, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		throw std::runtime_error(std::string("VirtualProtect failed !"));
	}

	// Copy the content of the fx
	memcpy(newfx, &fx, newfxsz);

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

	// Fix values
	*reinterpret_cast<intptr_t*>(newfx + 1 /*offset for func name*/) = (intptr_t)fxname;
	*reinterpret_cast<intptr_t*>(newfx + 6 /*offset for log fx*/) -= (intptr_t)((int)newfx - (int)&fx);	 // Since we copy the fx somewhere else, fix the relative jump
	*reinterpret_cast<intptr_t*>(newfx + 12 /*offset for jmp back*/) = (intptr_t)original;
}

int main()
{   			
	H(Beep);
	H(MessageBoxA);

	while (true)
	{
		Beep(1000, 10);
		MessageBoxA(NULL, "A", "B", NULL);
	}
}
