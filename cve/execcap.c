
#include <stdio.h>  
#include <unistd.h>  

  
int main()  
{  
    char *buf[] = {"showcap", NULL, NULL};
    execve("showcap", buf, NULL);
    return 0;  
}
