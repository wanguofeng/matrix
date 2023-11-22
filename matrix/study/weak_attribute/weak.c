#include <stdio.h>

// 定义一个弱引用的函数
__attribute__((weak)) void weak_func(void) {
    printf("This is a weak function.\n");
}

// 定义一个使用弱引用函数的函数
void use_weak_func(void) {
    // 调用弱引用函数
    weak_func();
}

int main() {
    // 调用使用弱引用函数
    use_weak_func();
    return 0;
}

