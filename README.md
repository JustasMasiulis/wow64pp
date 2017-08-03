# wow64pp
Easy to use utility for 32bit applications running in wow64 subsystem that need to interact with other 64bit processes.

The heart of the library ( call_function ) is based on [wow64ext](https://github.com/rwfpl/rewolf-wow64ext) X64Call.

## Installation

The library is a single header so all you need to do is copy it to your directory and include it.

## Quick reference
Wow64pp only exposes 3 functions 2 of which have exception based and error_code based counterparts.

```c++
#include "wow64pp.hpp"
// ...

// equalient of GetModuleHandle
auto x64_ntdll_handle = wow64pp::module_handle("ntdll.dll"); 
// or wow64pp::module_handle("ntdll.dll", error_code);

// equalient of GetProcAddress
auto x64_NtQueryVirtualMemory = wow64pp::procedure_address(x64_ntdll_handle, "NtQueryVirtualMemory"); 
// or wow64pp::procedure_address(x64_ntdll_handle, "NtQueryVirtualMemory", error_code);

// after getting the function address you can call it using wow64pp::call_function by passing its address
// as the first argument, with the function arguments following.
winapi::MEMORY_BASIC_INFORMATION64 memory_info;
std::uint64_t result_len;
auto ec = wow64pp::call_function(x64_NtQueryVirtualMemory, process_handle, address
				, 0, &memory_info, sizeof(memory_info), &result_len);
```
