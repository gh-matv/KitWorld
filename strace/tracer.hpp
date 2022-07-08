#pragma once

#include <Windows.h>

#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>

#define TRACE(fx) (setlog(&fx, #fx, #fx))

namespace Tracer
{
    // For stdcall fuckit
    template<typename T, typename... TParams>
    static int GetNumOfParams(T(__stdcall* t)(TParams...))
    {
        return sizeof...(TParams);
    }

    template<typename T, typename... TParams>
    static int GetNumOfParams(T(*t)(TParams...))
    {
        return sizeof...(TParams);
    }

    // ========================================================

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

}

