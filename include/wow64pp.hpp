/*
* Copyright 2017 Justas Masiulis
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef WOW64PP_HPP
#define WOW64PP_HPP

#include <system_error>
#include <memory>
#include <cstring> // memcpy

namespace wow64pp {

    namespace definitions {

        constexpr static unsigned long ProcessBasicInformation = 0;

        template<typename P>
        class PROCESS_BASIC_INFORMATION_T {
            P Reserved1;

        public:
            P PebBaseAddress;

        private:
            P Reserved2[2];
            P UniqueProcessId;
            P Reserved3;
        };

        template<class P>
        class PEB_T {
            unsigned char Reserved1[2];
            unsigned char BeingDebugged;
            unsigned char Reserved2[1];
            P             Reserved3[2];

        public:
            P Ldr;
        };

        template<typename P>
        struct LIST_ENTRY_T {
            P Flink;
            P Blink;
        };

        template<class P>
        struct PEB_LDR_DATA_T {
            unsigned long Length;
            unsigned long Initialized;
            P             SsHandle;

            LIST_ENTRY_T<P> InLoadOrderModuleList;
        };

        template<typename P>
        struct UNICODE_STRING_T {
            unsigned short Length;
            unsigned short MaximumLength;
            P              Buffer;
        };

        template<class P>
        struct LDR_DATA_TABLE_ENTRY_T {
            LIST_ENTRY_T<P> InLoadOrderLinks;

        private:
            LIST_ENTRY_T<P> InMemoryOrderLinks;
            LIST_ENTRY_T<P> InInitializationOrderLinks;

        public:
            P DllBase;

        private:
            P EntryPoint;
            union {
                unsigned long SizeOfImage;
                P             _dummy;
            };
            UNICODE_STRING_T<P> FullDllName;

        public:
            UNICODE_STRING_T<P> BaseDllName;
        };


        using NtQueryInformationProcessT = long(__stdcall*)(void* ProcessHandle
                                                                , unsigned long ProcessInformationClass
                                                                , void* ProcessInformation
                                                                , unsigned long ProcessInformationLength
                                                                , unsigned long* ReturnLength);


        using NtWow64ReadVirtualMemory64T = long(__stdcall*)(void* ProcessHandle, unsigned __int64 BaseAddress
                                                                 , void* Buffer, unsigned __int64 Size
                                                                 , unsigned __int64* NumberOfBytesRead);
        struct IMAGE_EXPORT_DIRECTORY {
            unsigned long   Characteristics;
            unsigned long   TimeDateStamp;
            unsigned short  MajorVersion;
            unsigned short  MinorVersion;
            unsigned long   Name;
            unsigned long   Base;
            unsigned long   NumberOfFunctions;
            unsigned long   NumberOfNames;
            unsigned long   AddressOfFunctions;     // RVA from base of image
            unsigned long   AddressOfNames;         // RVA from base of image
            unsigned long   AddressOfNameOrdinals;  // RVA from base of image
        };

        struct IMAGE_DOS_HEADER {      // DOS .EXE header
            unsigned short   e_magic;                     // Magic number
            unsigned short   e_cblp;                      // Bytes on last page of file
            unsigned short   e_cp;                        // Pages in file
            unsigned short   e_crlc;                      // Relocations
            unsigned short   e_cparhdr;                   // Size of header in paragraphs
            unsigned short   e_minalloc;                  // Minimum extra paragraphs needed
            unsigned short   e_maxalloc;                  // Maximum extra paragraphs needed
            unsigned short   e_ss;                        // Initial (relative) SS value
            unsigned short   e_sp;                        // Initial SP value
            unsigned short   e_csum;                      // Checksum
            unsigned short   e_ip;                        // Initial IP value
            unsigned short   e_cs;                        // Initial (relative) CS value
            unsigned short   e_lfarlc;                    // File address of relocation table
            unsigned short   e_ovno;                      // Overlay number
            unsigned short   e_res[4];                    // Reserved words
            unsigned short   e_oemid;                     // OEM identifier (for e_oeminfo)
            unsigned short   e_oeminfo;                   // OEM information; e_oemid specific
            unsigned short   e_res2[10];                  // Reserved words
            long             e_lfanew;                    // File address of new exe header
        };

        struct IMAGE_FILE_HEADER {
            unsigned short    Machine;
            unsigned short    NumberOfSections;
            unsigned long     TimeDateStamp;
            unsigned long     PointerToSymbolTable;
            unsigned long     NumberOfSymbols;
            unsigned short    SizeOfOptionalHeader;
            unsigned short    Characteristics;
        };

        struct IMAGE_DATA_DIRECTORY {
            unsigned long   VirtualAddress;
            unsigned long   Size;
        };

        struct IMAGE_OPTIONAL_HEADER64 {
            constexpr static std::size_t image_num_dir_entries = 16;
            unsigned short        Magic;
            unsigned char        MajorLinkerVersion;
            unsigned char        MinorLinkerVersion;
            unsigned long       SizeOfCode;
            unsigned long       SizeOfInitializedData;
            unsigned long       SizeOfUninitializedData;
            unsigned long       AddressOfEntryPoint;
            unsigned long       BaseOfCode;
            std::uint64_t   ImageBase;
            unsigned long       SectionAlignment;
            unsigned long       FileAlignment;
            unsigned short        MajorOperatingSystemVersion;
            unsigned short        MinorOperatingSystemVersion;
            unsigned short        MajorImageVersion;
            unsigned short        MinorImageVersion;
            unsigned short        MajorSubsystemVersion;
            unsigned short        MinorSubsystemVersion;
            unsigned long       Win32VersionValue;
            unsigned long       SizeOfImage;
            unsigned long       SizeOfHeaders;
            unsigned long       CheckSum;
            unsigned short        Subsystem;
            unsigned short        DllCharacteristics;
            std::uint64_t   SizeOfStackReserve;
            std::uint64_t   SizeOfStackCommit;
            std::uint64_t   SizeOfHeapReserve;
            std::uint64_t   SizeOfHeapCommit;
            unsigned long       LoaderFlags;
            unsigned long       NumberOfRvaAndSizes;
            IMAGE_DATA_DIRECTORY DataDirectory[image_num_dir_entries];
        };

        typedef struct _IMAGE_NT_HEADERS64 {
            unsigned long Signature;
            IMAGE_FILE_HEADER FileHeader;
            IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        } IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
    }


    namespace detail {

        constexpr static auto image_directory_entry_export = 0;
        constexpr static auto ordinal_not_found = 0xC0000138;

        typedef int (__stdcall *FARPROC)();

        extern "C" {

            __declspec(dllimport) unsigned long __stdcall GetLastError();

            __declspec(dllimport) void* __stdcall GetCurrentProcess();

            __declspec(dllimport) int __stdcall DuplicateHandle(
                void* hSourceProcessHandle,
                void* hSourceHandle,
                void* hTargetProcessHandle,
                void** lpTargetHandle,
                unsigned long dwDesiredAccess,
                int bInheritHandle,
                unsigned long dwOptions);

           __declspec(dllimport) void* __stdcall GetModuleHandleA(const char* lpModuleName);

           __declspec(dllimport) FARPROC __stdcall GetProcAddress(void* hModule, const char* lpProcName);
        }


        inline std::error_code get_last_error() noexcept
        {
            return std::error_code(static_cast<int>(GetLastError()), std::system_category());
        }


        inline void throw_last_error(const char* message)
        {
            throw std::system_error(get_last_error(), message);
        }


        inline void throw_if_failed(const char* message, int hr)
        {
            if (hr < 0)
                throw std::system_error(std::error_code(hr, std::system_category()), message);
        }

        inline void* self_handle()
        {
            void* h;

            if (DuplicateHandle(GetCurrentProcess()
                                , GetCurrentProcess()
                                , GetCurrentProcess()
                                , &h
                                , 0
                                , 0
                                , 0x00000002) == 0) // DUPLICATE_SAME_ACCESS
                throw_last_error("failed to duplicate current process handle");

            return h;
        }

        inline void* self_handle(std::error_code& ec) noexcept
        {
            void* h;

            if (DuplicateHandle(GetCurrentProcess()
                                , GetCurrentProcess()
                                , GetCurrentProcess()
                                , &h
                                , 0
                                , 0
                                , 0x00000002) == 0) // DUPLICATE_SAME_ACCESS
                ec = get_last_error();

            return h;
        }

        inline void* native_module_handle(const char* name)
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                throw_last_error("GetModuleHandleA() failed");

            return addr;
        }

        inline void* native_module_handle(const char* name, std::error_code& ec) noexcept
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                ec = get_last_error();

            return addr;
        }


        template<typename F>
        inline F native_ntdll_function(const char* name)
        {
            const static auto ntdll_addr = native_module_handle("ntdll.dll");
            auto              f          = reinterpret_cast<F>(detail::GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                throw_last_error("failed to get address of ntdll function");

            return f;
        }

        template<typename F>
        inline F native_ntdll_function(const char* name, std::error_code& ec) noexcept
        {
            const auto ntdll_addr = native_module_handle("ntdll.dll", ec);
            if (ec)
                return nullptr;

            const auto f = reinterpret_cast<F>(detail::GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                ec = detail::get_last_error();

            return f;
        }


        inline std::uint64_t peb_address()
        {
            const static auto NtWow64QueryInformationProcess64 =
                                      native_ntdll_function<definitions::NtQueryInformationProcessT>(
                                              "NtWow64QueryInformationProcess64");

            definitions::PROCESS_BASIC_INFORMATION_T<std::uint64_t> pbi;
            const auto                                              hres = NtWow64QueryInformationProcess64(
                    GetCurrentProcess()
                    , definitions::ProcessBasicInformation
                    , &pbi
                    , sizeof(pbi)
                    , nullptr);
            throw_if_failed("NtWow64QueryInformationProcess64() failed", hres);

            return pbi.PebBaseAddress;
        }

        inline std::uint64_t peb_address(std::error_code& ec) noexcept
        {
            const auto NtWow64QueryInformationProcess64                  =
                               native_ntdll_function<definitions::NtQueryInformationProcessT>(
                                       "NtWow64QueryInformationProcess64"
                                       , ec);
            if (ec)
                return 0;

            definitions::PROCESS_BASIC_INFORMATION_T<std::uint64_t> pbi;
            const auto hres = NtWow64QueryInformationProcess64(
                GetCurrentProcess()
                , definitions::ProcessBasicInformation
                , &pbi
                , sizeof(pbi)
                , nullptr);
            if (hres < 0)
                ec = detail::get_last_error();

            return pbi.PebBaseAddress;
        }


        template<typename P>
        inline void read_memory(std::uint64_t address, P* buffer, std::size_t size = sizeof(P))
        {
            if (address < std::numeric_limits<std::uint32_t>::max()) {
                std::memcpy(buffer, reinterpret_cast<const void*>(static_cast<std::uint32_t>(address)), size);
                return;
            }

            const static auto NtWow64ReadVirtualMemory64 =
                                      native_ntdll_function<definitions::NtWow64ReadVirtualMemory64T>(
                                              "NtWow64ReadVirtualMemory64");

            HANDLE h_self = self_handle();
            auto   hres   = NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
            CloseHandle(h_self);
            throw_if_failed("NtWow64ReadVirtualMemory64() failed", hres);
        }

        template<typename P>
        inline void read_memory(std::uint64_t address, P* buffer, std::size_t size, std::error_code& ec) noexcept
        {
            if (address < std::numeric_limits<std::uint32_t>::max()) {
                std::memcpy(buffer, reinterpret_cast<const void*>(static_cast<std::uint32_t>(address)), size);
                return;
            }

            const auto NtWow64ReadVirtualMemory64 = native_ntdll_function<definitions::NtWow64ReadVirtualMemory64T>(
                    "NtWow64ReadVirtualMemory64"
                    , ec);
            if (ec)
                return;

            HANDLE h_self = self_handle(ec);
            if (ec)
                return;
            auto hres = NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
            CloseHandle(h_self);
            if (hres < 0)
                ec = get_last_error();

            return;
        }


        template<typename T>
        inline T read_memory(std::uint64_t address)
        {
            typename std::aligned_storage<sizeof(T), std::alignment_of<T>::value>::type buffer;
            read_memory(address, &buffer, sizeof(T));
            return *static_cast<T*>(static_cast<void*>(&buffer));
        }

        template<typename T>
        inline T read_memory(std::uint64_t address, std::error_code& ec) noexcept
        {
            typename std::aligned_storage<sizeof(T), std::alignment_of<T>::value>::type buffer;
            read_memory(address, &buffer, sizeof(T), ec);
            return *static_cast<T*>(static_cast<void*>(&buffer));
        }

    }


    /** \brief An equalient of winapi GetModuleHandle function.
    *   \param[in] module_name The name of the module to get the handle of.
    *   \return    The handle to the module as a 64 bit integer.
    *   \exception Throws std::system_error on failure.
    */
    inline std::uint64_t module_handle(const std::string& module_name)
    {
        const auto ldr_base = detail::read_memory<definitions::PEB_T<std::uint64_t>>(detail::peb_address()).Ldr;

        const auto last_entry = ldr_base + offsetof(definitions::PEB_LDR_DATA_T<std::uint64_t>, InLoadOrderModuleList);

        definitions::LDR_DATA_TABLE_ENTRY_T<std::uint64_t> head;
        head.InLoadOrderLinks.Flink =
                detail::read_memory<definitions::PEB_LDR_DATA_T<std::uint64_t>>(ldr_base).InLoadOrderModuleList.Flink;

        do {
            try {
                detail::read_memory(head.InLoadOrderLinks.Flink, &head);
            }
            catch (std::system_error&) {
                continue;
            }

            const auto other_module_name_len = head.BaseDllName.Length / sizeof(wchar_t);
            if (other_module_name_len != module_name.length())
                continue;

            auto other_module_name = std::make_unique<wchar_t[]>(other_module_name_len);
            detail::read_memory(head.BaseDllName.Buffer, other_module_name.get(), head.BaseDllName.Length);

            if (std::equal(begin(module_name), end(module_name), other_module_name.get()))
                return head.DllBase;
        } while (head.InLoadOrderLinks.Flink != last_entry);

        throw std::system_error(std::error_code(detail::ordinal_not_found, std::system_category())
                                , "Could not get x64 module handle");
    }

    /** \brief An equalient of winapi GetModuleHandle function.
    *   \param[in] module_name The name of the module to get the handle of.
    *   \param[out] ec An error code that will be set in case of failure
    *   \return    The handle to the module as a 64 bit integer.
    *   \exception Does not throw.
    */
    inline std::uint64_t module_handle(const std::string& module_name, std::error_code& ec)
    {
        const auto ldr_base = detail::read_memory<definitions::PEB_T<std::uint64_t>>(detail::peb_address(ec), ec).Ldr;
        if (ec)
            return 0;

        const auto last_entry = ldr_base + offsetof(definitions::PEB_LDR_DATA_T<std::uint64_t>, InLoadOrderModuleList);

        definitions::LDR_DATA_TABLE_ENTRY_T<std::uint64_t> head;
        head.InLoadOrderLinks.Flink =
                detail::read_memory<definitions::PEB_LDR_DATA_T<std::uint64_t>>(ldr_base, ec).InLoadOrderModuleList
                        .Flink;
        if (ec)
            return 0;

        do {
            detail::read_memory(head.InLoadOrderLinks.Flink, &head, sizeof(head), ec);
            if (ec)
                continue;

            const auto other_module_name_len = head.BaseDllName.Length / sizeof(wchar_t);
            if (other_module_name_len != module_name.length())
                continue;

            auto other_module_name = std::make_unique<wchar_t[]>(other_module_name_len);
            detail::read_memory(head.BaseDllName.Buffer, other_module_name.get(), head.BaseDllName.Length, ec);
            if (ec)
                continue;

            if (std::equal(begin(module_name), end(module_name), other_module_name.get()))
                return head.DllBase;

        } while (head.InLoadOrderLinks.Flink != last_entry);

        if (!ec)
            ec = std::error_code(detail::ordinal_not_found, std::system_category());

        return 0;
    }


    namespace detail {

        inline definitions::IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base)
        {
            const auto e_lfanew = read_memory<definitions::IMAGE_DOS_HEADER>(ntdll_base).e_lfanew;

            const auto idd_virtual_addr = read_memory<definitions::IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew).OptionalHeader
                    .DataDirectory[image_directory_entry_export].VirtualAddress;

            if (idd_virtual_addr == 0)
                throw std::runtime_error("IMAGE_EXPORT_DIRECTORY::VirtualAddress was 0");

            return read_memory<definitions::IMAGE_EXPORT_DIRECTORY>(ntdll_base + idd_virtual_addr);
        }

        inline definitions::IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base, std::error_code& ec) noexcept
        {
            const auto e_lfanew = read_memory<definitions::IMAGE_DOS_HEADER>(ntdll_base, ec).e_lfanew;
            if (ec)
                return {};

            const auto idd_virtual_addr = read_memory<definitions::IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew, ec).OptionalHeader
                    .DataDirectory[image_directory_entry_export].VirtualAddress;
            if (ec)
                return {};

            if (idd_virtual_addr == 0) {
                ec = std::error_code(ordinal_not_found, std::system_category());
                return {};
            }

            return read_memory<definitions::IMAGE_EXPORT_DIRECTORY>(ntdll_base + idd_virtual_addr, ec);
        }


        inline std::uint64_t ldr_procedure_address()
        {
            const static auto ntdll_base = module_handle("ntdll.dll");

            const auto ied = image_export_dir(ntdll_base);

            auto rva_table = std::make_unique<unsigned long[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions, rva_table.get(), sizeof(unsigned long) * ied.NumberOfFunctions);

            auto ord_table = std::make_unique<unsigned short[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals, ord_table.get(), sizeof(unsigned short) * ied.NumberOfFunctions);

            auto name_table = std::make_unique<unsigned long[]>(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames, name_table.get(), sizeof(unsigned long) * ied.NumberOfNames);

            const std::string to_find("LdrGetProcedureAddress");
            std::string       buffer = to_find;

            const std::size_t
                             n =
                    (ied.NumberOfFunctions > ied.NumberOfNames ? ied.NumberOfNames : ied.NumberOfFunctions);
            for (std::size_t i = 0; i < n; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size());

                if (buffer == to_find)
                    return ntdll_base + rva_table[ord_table[i]];
            }

            throw std::system_error(std::error_code(ordinal_not_found, std::system_category())
                                    , "could find x64 LdrGetProcedureAddress()");
        }

        inline std::uint64_t ldr_procedure_address(std::error_code& ec)
        {
            const static auto ntdll_base = module_handle("ntdll.dll", ec);
            if (ec)
                return 0;

            const auto ied = image_export_dir(ntdll_base, ec);
            if (ec)
                return 0;

            auto rva_table = std::make_unique<unsigned long[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions
                        , rva_table.get()
                        , sizeof(unsigned long) * ied.NumberOfFunctions
                        , ec);
            if (ec)
                return 0;

            auto ord_table = std::make_unique<unsigned short[]>(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals
                        , ord_table.get()
                        , sizeof(unsigned short) * ied.NumberOfFunctions
                        , ec);
            if (ec)
                return 0;

            auto name_table = std::make_unique<unsigned long[]>(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames, name_table.get(), sizeof(unsigned long) * ied.NumberOfNames, ec);
            if (ec)
                return 0;

            const std::string to_find("LdrGetProcedureAddress");
            std::string       buffer;
            buffer.resize(to_find.size());

            const std::size_t n = ied.NumberOfFunctions > ied.NumberOfNames
                ? ied.NumberOfNames
                : ied.NumberOfFunctions;

            for (std::size_t  i = 0; i < n; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size(), ec);
                if (ec)
                    continue;

                if (buffer == to_find)
                    return ntdll_base + rva_table[ord_table[i]];
            }

            ec = std::error_code(ordinal_not_found, std::system_category());
            return 0;
        }

    }


    /** \brief Calls a 64 bit function from 32 bit process
    *   \param[in] func The address of 64 bit function to be called.
    *   \param[in] args... The arguments for the function to be called.
    *   \return    An error_code specifying whether the call succeeded.
    *   \exception Does not throw.
    */
    template<class... Args>
    inline std::uint64_t call_function(std::uint64_t func, Args... args)
    {
        std::uint64_t arr_args[] = { (std::uint64_t)(args)... };

        constexpr static std::uint8_t shellcode[] = {
                0x55,       // push ebp
                0x89, 0xE5, // mov ebp, esp

                0x83, 0xE4, 0xF0, // and esp, 0xFFFFFFF0

                // enter 64 bit mode
                0x6A, 0x33, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x83, 0x04, 0x24, 0x05, 0xCB, 

                0x67, 0x48, 0x8B, 0x4D, 16, // mov rcx, [ebp + 16]
                0x67, 0x48, 0x8B, 0x55, 24, // mov rdx, [ebp + 24]
                0x67, 0x4C, 0x8B, 0x45, 32, // mov r8,  [ebp + 32]
                0x67, 0x4C, 0x8B, 0x4D, 40, // mov r9,  [ebp + 40]

                0x67, 0x48, 0x8B, 0x45, 48, // mov rax, [ebp + 48] args count


                0xA8, 0x01,             // test al, 1
                0x75, 0x04,             // jne 8, _no_adjust
                0x48, 0x83, 0xEC, 0x08, // sub rsp, 8
                // _no adjust:
                0x57,                                     // push rdi
                0x67, 0x48, 0x8B, 0x7D, 0x38,             // mov rdi, [ebp + 56]
                0x48, 0x85, 0xC0,                         // je _ls_e
                0x74, 0x16, 0x48, 0x8D, 0x7C, 0xC7, 0xF8, // lea rdi,[rdi+rax*8-8]
                // _ls:
                0x48, 0x85, 0xC0,       // test rax, rax
                0x74, 0x0C,             // je _ls_e
                0xFF, 0x37,             // push [rdi]
                0x48, 0x83, 0xEF, 0x08, // sub rdi, 8
                0x48, 0x83, 0xE8, 0x01, // sub rax, 1
                0xEB, 0xEF,             // jmp _ls
                // _ls_e:
                0x67, 0x8B, 0x7D, 0x40,       // mov edi, [ebp + 64]
                0x48, 0x83, 0xEC, 0x20,       // sub rsp, 0x20
                0x67, 0xFF, 0x55, 0x08,       // call [ebp + 0x8]
                0x67, 0x89, 0x07,             // mov [edi], eax
                0x67, 0x48, 0x8B, 0x4D, 0x30, // mov rcx, [ebp+48]
                0x48, 0x8D, 0x64, 0xCC, 0x20, // lea rsp,[rsp+rcx*8+0x20]
                0x5F,                         // pop rdi

                // exit 64 bit mode
                0xE8, 0, 0, 0, 0, 0xC7,0x44, 0x24, 4, 0x23, 0, 0, 0, 0x83, 4, 0x24, 0xD, 0xCB, 

                0x66, 0x8C, 0xD8, // mov ax, ds
                0x8E, 0xD0,       // mov ss, eax

                0x89, 0xEC, // mov esp, ebp
                0x5D,       // pop ebp
                0xC3        // ret
        };

        static void *allocated_shellcode = [] {
            //                                                  MEM_COMMIT   MEM_RESERVE PAGE_EXECUTE_READWRITE
            auto mem = VirtualAlloc(nullptr, sizeof(shellcode), 0x00001000 | 0x00002000, 0x40);
            if (!mem)
                detail::throw_last_error("VirtualAlloc failed to allocate memory for call_function shellcode");

            std::memcpy(mem, shellcode, sizeof(shellcode));
            return mem;
        }();
 
        using my_fn_sig = void(__cdecl*)(std::uint64_t, std::uint64_t, std::uint64_t
                                         , std::uint64_t, std::uint64_t, std::uint64_t
                                         , std::uint64_t, std::uint32_t);

        std::uint32_t ret;
        reinterpret_cast<my_fn_sig>(allocated_shellcode)(func
                                           , arr_args[0]
                                           , arr_args[1]
                                           , arr_args[2]
                                           , arr_args[3]
                                           , sizeof...(Args) > 4 ? (sizeof...(Args) - 4) : 0
                                           , reinterpret_cast<std::uint64_t>(arr_args + 4)
                                           , reinterpret_cast<std::uint32_t>(&ret));

        return ret;
    }


    /** \brief An equalient of winapi GetProcAddress function.
    *   \param[in] hmodule The handle to the module in which to search for the procedure.
    *   \param[in] procedure_name The name of the procedure to be searched for.
    *   \return    The address of the exported function or variable.
    *   \exception Throws std::system_error on failure.
    */
    inline std::uint64_t import(std::uint64_t hmodule, const std::string& procedure_name)
    {
        const static auto ldr_procedure_address_base = detail::ldr_procedure_address();

        definitions::UNICODE_STRING_T<std::uint64_t> unicode_fun_name;
        unicode_fun_name.Buffer        = reinterpret_cast<std::uint64_t>(&procedure_name[0]);
        unicode_fun_name.Length        = static_cast<unsigned short>(procedure_name.size());
        unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;

        std::uint64_t ret;
        auto          fn_ret           = call_function(ldr_procedure_address_base
                                                       , hmodule
                                                       , reinterpret_cast<std::uint64_t>(&unicode_fun_name)
                                                       , static_cast<std::uint64_t>(0)
                                                       , reinterpret_cast<std::uint64_t>(&ret));
        if (fn_ret)
            throw std::system_error(std::error_code(static_cast<int>(fn_ret), std::system_category())
                                    , "call_function(ldr_procedure_address_base...) failed");

        return ret;
    }

    /** \brief An equalient of winapi GetProcAddress function.
    *   \param[in] hmodule The handle to the module in which to search for the procedure.
    *   \param[in] procedure_name The name of the procedure to be searched for.
    *   \param[out] ec An error code that will be set in case of failure
    *   \return    The address of the exported function or variable.
    *   \exception Does not throw.
    */
    inline std::uint64_t import(std::uint64_t hmodule, const std::string& procedure_name, std::error_code& ec)
    {
        const static auto ldr_procedure_address_base = detail::ldr_procedure_address(ec);
        if (ec)
            return 0;

        definitions::UNICODE_STRING_T<std::uint64_t> unicode_fun_name;
        unicode_fun_name.Buffer        = reinterpret_cast<std::uint64_t>(&procedure_name[0]);
        unicode_fun_name.Length        = static_cast<unsigned short>(procedure_name.size());
        unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;

        std::uint64_t ret;
        auto fn_ret = call_function(ldr_procedure_address_base
                           , hmodule
                           , reinterpret_cast<std::uint64_t>(&unicode_fun_name)
                           , static_cast<std::uint64_t>(0)
                           , reinterpret_cast<std::uint64_t>(&ret));

        return ret;
    }

}

#endif // #ifndef WOW64PP_HPP
