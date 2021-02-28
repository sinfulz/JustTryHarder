This binary can be executed to spawn a shell. Let's create a binary to start cmd.exe. Create a file named pwn.c with the contents:
  
```  
  #include <stdlib.h>
  
  int main() {
    system("C:\\Windows\\System32\\cmd.exe");
}
```

The C code above spawns cmd.exe on execution. This can be compiled using mingw on Linux.

```  
$ apt install mingw-w64
$ x86_64-w64-mingw32-gcc pwn.c -o pwn.exe
```
