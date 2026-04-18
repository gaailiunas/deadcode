#include <iostream>

int main(void)
{
    int x = 0;
    for (int i = 0; i < 5; i++) {
        x += 20;
    }
    if (x == 2) {
        std::cout << "x=2" << std::endl;
    }
    else {
        std::cout << "x!=2" << std::endl;
    }
    return 0;
}