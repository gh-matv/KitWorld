// Logger.cpp : Ce fichier contient la fonction 'main'. L'exécution du programme commence et se termine à cet endroit.
//

#include <Windows.h>
#include <iostream>

struct A
{
    unsigned int i : 1;
    // unsigned int j : 7;
};

int main()
{
    A a;
    a.i = 0;
    a.i++;
    std::cout << ++a.i << " " << ++a.i << std::endl;
    return 0;
}