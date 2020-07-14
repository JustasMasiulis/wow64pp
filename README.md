# wow64pp
An easy to use header only heavens gate implementation based on [wow64ext](https://github.com/rwfpl/rewolf-wow64ext) X64Call however not using inline assembly allowing it to work on other compilers like MinGW.

## Quick reference
Wow64pp only exposes 3 functions 2 of which have exception based and error_code based counterparts.

```c++
#include "wow64pp.hpp"
// ...

// equivalent of GetModuleHandle
auto x64_ntdll_handle = wow64pp::module_handle("ntdll.dll"); 
// or wow64pp::module_handle("ntdll.dll", error_code);

// equivalent of GetProcAddress
auto x64_NtQueryVirtualMemory = wow64pp::import(x64_ntdll_handle, "NtQueryVirtualMemory"); 
// or wow64pp::import(x64_ntdll_handle, "NtQueryVirtualMemory", error_code);

// after getting the function address you can call it using wow64pp::call_function by passing its address
// as the first argument, with the function arguments following.
winapi::MEMORY_BASIC_INFORMATION64 memory_info;
std::uint64_t result_len;
auto ec = wow64pp::call_function(x64_NtQueryVirtualMemory, process_handle, address
				, 0, &memory_info, sizeof(memory_info), &result_len);
```
