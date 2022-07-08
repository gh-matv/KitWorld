// Logger.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <Windows.h>
#include <iostream>

// For stdcall fuckit
template<typename T, typename... TParams>
int GetNumOfParams(T( __stdcall *t)(TParams...))
{
    return sizeof...(TParams);
}

template<typename T, typename... TParams>
int GetNumOfParams(T (*t)(TParams...))
{
    return sizeof...(TParams);
}

int main(int argc, char *argv[])
{
    std::cout << GetNumOfParams(MessageBoxA) << std::endl;
}

