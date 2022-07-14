#pragma once

#include <Windows.h>

#include <map>
#include <vector>

#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/CapstoneDisassembler.hpp>

#define TRACE(fx) (Tracer::setlog(&fx, #fx, Tracer::GetParams(fx)))

namespace Tracer
{

    struct FuncParamTypeInfos
    {
        std::string paramname;
        bool is_ptr;
        size_t size;
        enum {OTH, INT, STR} type;

        static std::string type_to_string(int type)
        {
            switch (type)
            {
            case OTH:
                return "UNKNOWN";
            case INT:
                return "INT";
            case STR:
                return "STR";
            }
        }
    };

    struct OrigFuncInfos
    {
        const char* funcName;
        std::vector<FuncParamTypeInfos> paramTypes;
    };


    std::map<void*, OrigFuncInfos> mFuncOriginalInfos;

    PLH::CapstoneDisassembler dis(PLH::Mode::x86);
    std::vector<std::shared_ptr<PLH::x86Detour>> detours;

    // For stdcall fuckit
    template<typename T, typename... TParams>
    static int GetNumOfParams(T(__stdcall* t)(TParams...))
    {
        return sizeof...(TParams);
    }

    template<typename T, typename... TParams>
    static std::vector<FuncParamTypeInfos> GetParams(T(__stdcall* t)(TParams...))
    {
        std::vector<FuncParamTypeInfos> names;

        //int dummy[sizeof...(TParams)] = { (std::cout << typeid(TParams).name() << std::endl, 0)...};
        int dummy[sizeof...(TParams)] = { (
            names.push_back(
                {
                    typeid(TParams).name(),                   // name
                    (std::string(typeid(TParams).name()).find("*") != std::string::npos) ? true : false, // is_pointer
                    sizeof(TParams),                                                                                  // size
                    (std::string(typeid(TParams).name()).find("char const *") != std::string::npos) ? FuncParamTypeInfos::STR : FuncParamTypeInfos::INT // type
                }
            ), 0)... };
        return names;
    }

    // ========================================================

    void logger_fx(const char* hook_address) noexcept
    {
        std::stringstream ss;
        auto x = mFuncOriginalInfos[(void*)hook_address];

        ss << "Called " << x.funcName << "\n";
        for (auto p : x.paramTypes)
            ss << "\t" << p.paramname << "=" << FuncParamTypeInfos::type_to_string(p.type) << "\tsz=" << p.size << "\n";
        std::cout << ss.str() << std::endl;
    }

    //#pragma const_seg(".t_const")
#pragma optimize("", off)
    __declspec(naked) void fx() noexcept
    {
        // 00D53AD0 BA 44 32 2A 00       mov         edx, offset string "Beep" (02A3244h)
        // 00D53ADA E8 41 40 FC D4       call        D5D17B20
        // Address offset = 6
        logger_fx((const char*)0x42424242);

        __asm nop
        __asm push 0x12345677											//	<- to fix with the correct pointer to the original function
        __asm ret
    }
    __declspec(naked) void fxend() {}
#pragma optimize("", on)
    //#pragma const_seg()

    template<typename T>
    void setlog(T* function_to_hook, const char* fxname = "", std::vector<FuncParamTypeInfos>&& functionparams = {})
    {

        // Allocate memory for the function and make it executable
        DWORD oldProtect;
        auto newfxsz = (int)&fxend - (int)&fx;
        char* newfx = (char*)malloc(newfxsz);

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
        detours.push_back(std::make_shared<PLH::x86Detour>((const uint64_t)function_to_hook, (const uint64_t)newfx64, (uint64_t*)&original, dis));
        detours.back()->hook();

        // Fix values
        *reinterpret_cast<intptr_t*>(newfx + 1 /*offset for func name*/) =          (intptr_t)newfx;
        //*reinterpret_cast<intptr_t*>(newfx + 11 /*offset for func param count*/) =  (intptr_t)GetNumOfParams(function_to_hook);
        *reinterpret_cast<intptr_t*>(newfx + 6 /*offset for log fx*/) -= (intptr_t)((int)newfx - (int)&fx);	 // Since we copy the fx somewhere else, fix the relative jump
        *reinterpret_cast<intptr_t*>(newfx + 12 /*offset for jmp back*/) =          (intptr_t)original;

        OrigFuncInfos ofi{
            .funcName = fxname ,
            .paramTypes = functionparams
        };

        mFuncOriginalInfos.insert(std::make_pair(newfx, ofi)); 
    }

}

