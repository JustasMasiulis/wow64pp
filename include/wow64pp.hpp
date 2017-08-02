


#ifndef WOW64PP_HPP
#define WOW64PP_HPP

#include <system_error>
#include <vector>
#include <array>

namespace wow64pp
{

#include <Windows.h>
#include <winternl.h>


    namespace definitions
    {
        // I add only what I need to these structures

        template<typename P>
        struct PROCESS_BASIC_INFORMATION_T
        {
        private:
            P Reserved1;

        public:
            P PebBaseAddress;

        private:
            P Reserved2[2];
            P UniqueProcessId;
            P Reserved3;
        };


        template <class P>
        struct PEB_T
        {
        private:
            BYTE Reserved1[2];
            BYTE BeingDebugged;
            BYTE Reserved2[1];
            P    Reserved3[2];

        public:
            P    Ldr;
        };


        template<typename P>
        struct LIST_ENTRY_T {
            P Flink;
            P Blink;
        };


        template <class P>
        struct PEB_LDR_DATA_T
        {
        private:
            DWORD Length;
            DWORD Initialized;
            P     SsHandle;

        public:
            LIST_ENTRY_T<P> InLoadOrderModuleList;
        };


        template<typename P>
        struct UNICODE_STRING_T {
            USHORT Length;
            USHORT MaximumLength;
            P      Buffer;
        };


        template <class P>
        struct LDR_DATA_TABLE_ENTRY_T
        {
        public:
            LIST_ENTRY_T<P> InLoadOrderLinks;
        private:
            LIST_ENTRY_T<P> InMemoryOrderLinks;
            LIST_ENTRY_T<P> InInitializationOrderLinks;

        public:
            P               DllBase;

        private:
            P               EntryPoint;
            union
            {
                DWORD SizeOfImage;
                P     _dummy;
            };
            UNICODE_STRING_T<P> FullDllName;

        public:
            UNICODE_STRING_T<P> BaseDllName;
        };


        using  NtQueryInformationProcessT = NTSTATUS(NTAPI *)(
            HANDLE ProcessHandle,
            DWORD ProcessInformationClass,
            PVOID ProcessInformation,
            DWORD ProcessInformationLength,
            PDWORD ReturnLength);


        using NtWow64ReadVirtualMemory64T = NTSTATUS(NTAPI *)(
            IN HANDLE ProcessHandle,
            IN DWORD64 BaseAddress,
            OUT PVOID Buffer,
            IN ULONG64 Size,
            OUT PULONG64 NumberOfBytesRead);


        using RtlNtStatusToDosErrorT = ULONG(WINAPI *)(NTSTATUS);


        union reg64
        {
            DWORD64 v;
            DWORD   dw[2];
        };


#define WOW64PP_EMIT(a) __asm __emit (a)

#define WOW64PP_X64_POP(r) WOW64PP_EMIT(0x48 | ((r) >> 3)) WOW64PP_EMIT(0x58 | ((r) & 7))

#define WOW64PP_REX_W WOW64PP_EMIT(0x48) __asm

    }


    namespace detail
    {

        inline std::error_code get_last_error() noexcept
        {
            return std::error_code(static_cast<int>(GetLastError()), std::system_category());
        }


        inline void throw_last_error(const char* message)
        {
            throw std::system_error(get_last_error(), message);
        }


        inline void throw_if_failed(const char* message, HRESULT hr)
        {
            if (FAILED(hr))
                throw std::system_error(std::error_code(static_cast<int>(hr), std::system_category())
                                        , message);
        }

        inline HANDLE self_handle()
        {
            static HANDLE h = INVALID_HANDLE_VALUE;

            if (DuplicateHandle(GetCurrentProcess()
                , GetCurrentProcess()
                , GetCurrentProcess()
                , &h
                , 0
                , FALSE
                , DUPLICATE_SAME_ACCESS) == 0)
                throw_last_error("failed to duplicate current process handle");

            return h;
        }

        inline HANDLE self_handle(std::error_code& ec) noexcept
        {
            static HANDLE h = INVALID_HANDLE_VALUE;

            if (DuplicateHandle(GetCurrentProcess()
                , GetCurrentProcess()
                , GetCurrentProcess()
                , &h
                , 0
                , FALSE
                , DUPLICATE_SAME_ACCESS) == 0)
                ec = get_last_error();

            return h;
        }


        template<std::size_t Idx, bool OOB, typename T>
        struct get_or_0_impl_t
        {
            constexpr std::uint64_t operator()(const T& tuple)
            {
                return std::get<Idx>(tuple);
            }
        };

        template<std::size_t Idx, typename T>
        struct get_or_0_impl_t<Idx, true, T>
        {
            constexpr std::uint64_t operator()(const T& tuple)
            {
                return 0;
            }
        };

        template<std::size_t Idx, std::size_t Size, typename T>
        decltype(auto) get_or_0(T& tuple)
        {
            return get_or_0_impl_t<Idx, Idx >= Size, T>{}(tuple);
        }


        inline HMODULE native_module_handle(const char* name)
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                detail::throw_last_error("GetModuleHandleA  returned NULL");

            return addr;
        }

        inline HMODULE native_module_handle(const char* name, std::error_code& ec) noexcept
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                ec = detail::get_last_error();

            return addr;
        }


        template <typename F>
        inline F native_ntdll_function(const char* name)
        {
            const static auto ntdll_addr = native_module_handle("ntdll.dll");
            auto f = reinterpret_cast<F>(GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                detail::throw_last_error("failed to get address of ntdll function");

            return f;
        }

        template <typename F>
        inline F native_ntdll_function(const char* name, std::error_code& ec) noexcept
        {
            const auto ntdll_addr = native_module_handle("ntdll.dll", ec);
            if (ec)
                return nullptr;

            const auto f = reinterpret_cast<F>(GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                ec = detail::get_last_error();

            return f;
        }

        inline std::uint64_t peb_address()
        {
            const static auto NtWow64QueryInformationProcess64
                = native_ntdll_function<definitions::NtQueryInformationProcessT>("NtWow64QueryInformationProcess64");

            definitions::PROCESS_BASIC_INFORMATION_T<std::uint64_t> pbi;
            auto hres = NtWow64QueryInformationProcess64(GetCurrentProcess()
                                                         , ProcessBasicInformation
                                                         , &pbi
                                                         , sizeof(pbi)
                                                         , nullptr);
            detail::throw_if_failed("NtWow64QueryInformationProcess64() failed", hres);

            return pbi.PebBaseAddress;
        }

        inline std::uint64_t peb_address(std::error_code& ec) noexcept
        {
            const auto NtWow64QueryInformationProcess64
                = native_ntdll_function<definitions::NtQueryInformationProcessT>("NtWow64QueryInformationProcess64", ec);
            if (ec)
                return 0;

            definitions::PROCESS_BASIC_INFORMATION_T<std::uint64_t> pbi;
            auto hres = NtWow64QueryInformationProcess64(GetCurrentProcess()
                                                         , ProcessBasicInformation
                                                         , &pbi
                                                         , sizeof(pbi)
                                                         , nullptr);
            if (FAILED(hres))
                ec = detail::get_last_error();

            return pbi.PebBaseAddress;
        }


        template<typename P>
        inline void read_memory(std::uint64_t address, P* buffer, std::size_t size = sizeof(P))
        {
            const static auto NtWow64ReadVirtualMemory64
                = native_ntdll_function<definitions::NtWow64ReadVirtualMemory64T>("NtWow64ReadVirtualMemory64");

            HANDLE h_self = self_handle();
            auto hres = NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
            CloseHandle(h_self);
            throw_if_failed("NtWow64ReadVirtualMemory64() failed", hres);
        }

        template<typename P>
        inline void read_memory(std::uint64_t address, P* buffer, std::size_t size, std::error_code& ec) noexcept
        {
            const auto NtWow64ReadVirtualMemory64
                = native_ntdll_function<definitions::NtWow64ReadVirtualMemory64T>("NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return;

            HANDLE h_self = self_handle(ec);
            if (ec)
                return;
            auto hres = NtWow64ReadVirtualMemory64(h_self, address, buffer, size, nullptr);
            CloseHandle(h_self);
            if (FAILED(hres))
                ec = get_last_error();

            return;
        }


        template<typename T>
        inline T read_memory(std::uint64_t address)
        {
            T buffer;
            read_memory(address, &buffer);
            return buffer;
        }

        template<typename T>
        inline T read_memory(std::uint64_t address, std::error_code& ec) noexcept
        {
            T buffer;
            memset(&buffer, 0, sizeof(T));
            if (ec)
                return buffer;

            read_memory(address, &buffer, sizeof(T), ec);
            return buffer;
        }

    }

    inline std::uint64_t module_handle(const std::string& module_name)
    {
        const auto ldr_base = detail::read_memory<definitions::PEB_T<std::uint64_t>>(detail::peb_address()).Ldr;

        const auto last_entry = ldr_base
            + offsetof(definitions::PEB_LDR_DATA_T<std::uint64_t>, InLoadOrderModuleList);

        definitions::LDR_DATA_TABLE_ENTRY_T<std::uint64_t> head;
        head.InLoadOrderLinks.Flink = detail::read_memory<definitions::PEB_LDR_DATA_T<std::uint64_t>>(ldr_base)
            .InLoadOrderModuleList.Flink;

        do {
            try
            {
                detail::read_memory(head.InLoadOrderLinks.Flink, &head);
            }
            catch (std::system_error)
            {
                continue;
            }

            const auto other_module_name_len = head.BaseDllName.Length / sizeof(wchar_t);
            if (other_module_name_len != module_name.length())
                continue;

            std::vector<wchar_t> other_module_name(other_module_name_len);
            detail::read_memory(head.BaseDllName.Buffer, other_module_name.data(), head.BaseDllName.Length);

            if (std::equal(begin(module_name), end(module_name), begin(other_module_name)))
                return head.DllBase;
        } while (head.InLoadOrderLinks.Flink != last_entry);

        throw std::system_error(std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category())
                                , "Could not get x64 module handle");
    }

    inline std::uint64_t module_handle(const std::string& module_name, std::error_code& ec)
    {
        const auto ldr_base = detail::read_memory<definitions::PEB_T<std::uint64_t>>(detail::peb_address(ec), ec).Ldr;
        if (ec)
            return 0;

        const auto last_entry = ldr_base
            + offsetof(definitions::PEB_LDR_DATA_T<std::uint64_t>, InLoadOrderModuleList);

        definitions::LDR_DATA_TABLE_ENTRY_T<std::uint64_t> head;
        head.InLoadOrderLinks.Flink = detail::read_memory<definitions::PEB_LDR_DATA_T<std::uint64_t>>(ldr_base, ec)
            .InLoadOrderModuleList.Flink;
        if (ec)
            return 0;

        do {
            detail::read_memory(head.InLoadOrderLinks.Flink, &head, sizeof(head), ec);
            if (ec)
                continue;

            const auto other_module_name_len = head.BaseDllName.Length / sizeof(wchar_t);
            if (other_module_name_len != module_name.length())
                continue;

            std::vector<wchar_t> other_module_name(other_module_name_len);
            detail::read_memory(head.BaseDllName.Buffer, other_module_name.data(), head.BaseDllName.Length, ec);
            if (ec)
                continue;

            if (std::equal(begin(module_name), end(module_name), begin(other_module_name)))
                return head.DllBase;

        } while (head.InLoadOrderLinks.Flink != last_entry);

        if (!ec)
            ec = std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category());
    }

    namespace detail
    {

        inline IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base)
        {
            const auto e_lfanew = read_memory<IMAGE_DOS_HEADER>(ntdll_base).e_lfanew;

            const auto idd_virtual_addr = read_memory<IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew)
                .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                .VirtualAddress;

            if (idd_virtual_addr == 0)
                throw std::runtime_error("IMAGE_EXPORT_DIRECTORY::VirtualAddress was 0");

            return read_memory<IMAGE_EXPORT_DIRECTORY>(ntdll_base + idd_virtual_addr);
        }

        inline IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base, std::error_code& ec) noexcept
        {
            const auto e_lfanew = read_memory<IMAGE_DOS_HEADER>(ntdll_base, ec).e_lfanew;
            if (ec)
                return {};

            const auto idd_virtual_addr = read_memory<IMAGE_NT_HEADERS64>(ntdll_base + e_lfanew, ec)
                .OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                .VirtualAddress;
            if (ec)
                return {};

            if (idd_virtual_addr == 0) {
                ec = std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category());
                return {};
            }

            return read_memory<IMAGE_EXPORT_DIRECTORY>(ntdll_base + idd_virtual_addr, ec);
        }


        inline std::uint64_t ldr_procedure_address()
        {
            const static auto ntdll_base = module_handle("ntdll.dll");

            const auto ied = image_export_dir(ntdll_base);

            std::vector<DWORD> rva_table(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions, rva_table.data(), sizeof(DWORD) * ied.NumberOfFunctions);

            std::vector<WORD> ord_table(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals, ord_table.data(), sizeof(WORD) * ied.NumberOfFunctions);

            std::vector<DWORD> name_table(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames, name_table.data(), sizeof(DWORD) * ied.NumberOfNames);

            const std::string to_find("LdrGetProcedureAddress");
            std::string buffer = to_find;

            const std::size_t n = min(ied.NumberOfFunctions, ied.NumberOfNames);
            for (std::size_t i = 0; i < n; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size());

                if (buffer == to_find)
                    return ntdll_base + rva_table[ord_table[i]];
            }

            throw std::system_error(std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category())
                                    , "Could find x64 LdrGetProcedureAddress");
        }

        inline std::uint64_t ldr_procedure_address(std::error_code& ec)
        {
            const static auto ntdll_base = module_handle("ntdll.dll", ec);
            if (ec)
                return 0;

            const auto ied = image_export_dir(ntdll_base, ec);
            if (ec)
                return 0;

            std::vector<DWORD> rva_table(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions, rva_table.data(), sizeof(DWORD) * ied.NumberOfFunctions, ec);
            if (ec)
                return 0;

            std::vector<WORD> ord_table(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals, ord_table.data(), sizeof(WORD) * ied.NumberOfFunctions, ec);
            if (ec)
                return 0;

            std::vector<DWORD> name_table(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames, name_table.data(), sizeof(DWORD) * ied.NumberOfNames, ec);
            if (ec)
                return 0;

            const std::string to_find("LdrGetProcedureAddress");
            std::string buffer = to_find;

            const std::size_t n = min(ied.NumberOfFunctions, ied.NumberOfNames);
            for (std::size_t i = 0; i < n; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size(), ec);
                if (ec)
                    continue;

                if (buffer == to_find)
                    return ntdll_base + rva_table[ord_table[i]];
            }

            ec = std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category());
            return 0;
        }

    }

        // taken from https://github.com/rwfpl/rewolf-wow64ext
#pragma warning(push)
#pragma warning(disable : 4409) // illegal instruction size
    template<typename... Args>
    inline std::error_code call_function(std::uint64_t func, const Args&... args)
    {
        std::array<std::uint64_t, sizeof... (args)> arr_args{ std::uint64_t(args)... };

        definitions::reg64 _rcx{ detail::get_or_0<0, sizeof... (args)>(arr_args) };
        definitions::reg64 _rdx{ detail::get_or_0<1, sizeof... (args)>(arr_args) };
        definitions::reg64 _r8 { detail::get_or_0<2, sizeof... (args)>(arr_args) };
        definitions::reg64 _r9 { detail::get_or_0<3, sizeof... (args)>(arr_args) };
        definitions::reg64 _rax{ 0 };

        definitions::reg64 restArgs = { (static_cast<int>(sizeof... (args)) - 4 > 0)
            ? reinterpret_cast<std::uint64_t>(&arr_args[4])
            : 0 };

        // conversion to QWORD for easier use in inline assembly
        definitions::reg64 _argC = { static_cast<uint64_t>(max(sizeof... (args) - 4, 0)) };
        DWORD back_esp = 0;
        WORD  back_fs = 0;

        __asm
        {
            ;// reset FS segment, to properly handle RFG
            mov back_fs, fs
            mov eax, 0x2B
            mov fs, ax

                ;// keep original esp in back_esp variable
            mov back_esp, esp

                ;// align esp to 0x10, without aligned stack some syscalls may return errors !
            ;// (actually, for syscalls it is sufficient to align to 8, but SSE opcodes 
            ;// requires 0x10 alignment), it will be further adjusted according to the
            ;// number of arguments above 4
            and esp, 0xFFFFFFF0

            WOW64PP_EMIT(0x6A) WOW64PP_EMIT(0x33)                        /*  push   _cs             */ 
            WOW64PP_EMIT(0xE8) WOW64PP_EMIT(0) WOW64PP_EMIT(0) WOW64PP_EMIT(0) WOW64PP_EMIT(0)   /*  call   $+5             */ 
            WOW64PP_EMIT(0x83) WOW64PP_EMIT(4) WOW64PP_EMIT(0x24) WOW64PP_EMIT(5)        /*  add    dword [esp], 5  */ 
            WOW64PP_EMIT(0xCB)

            ;// below code is compiled as x86 inline asm, but it is executed as x64 code
            ;// that's why it need sometimes WOW64PP_REX_W() macro, right column contains detailed
            ;// transcription how it will be interpreted by CPU

            ;// fill first four arguments
            WOW64PP_REX_W mov ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
            WOW64PP_REX_W mov edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
            push _r8.v;// push    qword ptr [_r8]
            WOW64PP_X64_POP(8); ;// pop     r8
            push _r9.v;// push    qword ptr [_r9]
            WOW64PP_X64_POP(9); ;// pop     r9
            ;//
            WOW64PP_REX_W mov eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
            ;// 
            ;// final stack adjustment, according to the    ;//
            ;// number of arguments above 4                 ;// 
            test al, 1;// test    al, 1
            jnz _no_adjust;// jnz     _no_adjust
            sub esp, 8;// sub     rsp, 8
        _no_adjust:;//
            ;// 
            push edi;// push    rdi
            WOW64PP_REX_W mov edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
            ;// 
            ;// put rest of arguments on the stack          ;// 
            WOW64PP_REX_W test eax, eax;// test    rax, rax
            jz _ls_e;// je      _ls_e
            WOW64PP_REX_W lea edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
            ;// 
        _ls:;// 
            WOW64PP_REX_W test eax, eax;// test    rax, rax
            jz _ls_e;// je      _ls_e
            push dword ptr[edi];// push    qword ptr [rdi]
            WOW64PP_REX_W sub edi, 8;// sub     rdi, 8
            WOW64PP_REX_W sub eax, 1;// sub     rax, 1
            jmp _ls;// jmp     _ls
        _ls_e:;// 
            ;// 
            ;// create stack space for spilling registers   ;// 
            WOW64PP_REX_W sub esp, 0x20;// sub     rsp, 20h
            ;// 
            call func;// call    qword ptr [func]
            ;// 
            ;// cleanup stack                               ;// 
            WOW64PP_REX_W mov ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
            WOW64PP_REX_W lea esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
            ;// 
            pop edi;// pop     rdi
            ;// 
                // set return value                             ;// 
            WOW64PP_REX_W mov _rax.dw[0], eax;// mov     qword ptr [_rax], rax

            WOW64PP_EMIT(0xE8) WOW64PP_EMIT(0) WOW64PP_EMIT(0) WOW64PP_EMIT(0) WOW64PP_EMIT(0)                                  /*  call   $+5                   */ 
            WOW64PP_EMIT(0xC7) WOW64PP_EMIT(0x44) WOW64PP_EMIT(0x24) WOW64PP_EMIT(4) WOW64PP_EMIT(0x23) WOW64PP_EMIT(0) WOW64PP_EMIT(0) WOW64PP_EMIT(0) /*  mov    dword [rsp + 4], _cs  */ 
            WOW64PP_EMIT(0x83) WOW64PP_EMIT(4) WOW64PP_EMIT(0x24) WOW64PP_EMIT(0xD)                                     /*  add    dword [rsp], 0xD      */ 
            WOW64PP_EMIT(0xCB)                                                                  /*  retf                         */ 

            mov ax, ds
                mov ss, ax
                mov esp, back_esp

                ;// restore FS segment
            mov ax, back_fs
                mov fs, ax
        }

        return (_rax.v != 0 ? std::error_code(static_cast<int>(_rax.v), std::system_category()) : std::error_code{});
    }
#pragma warning(pop)

    inline std::uint64_t procedure_address(std::uint64_t hmodule, const std::string& procedure_name)
    {
        const static auto ldr_procedure_address_base = detail::ldr_procedure_address();

        definitions::UNICODE_STRING_T<std::uint64_t> unicode_fun_name;
        unicode_fun_name.Buffer = reinterpret_cast<std::uint64_t>(&procedure_name[0]);
        unicode_fun_name.Length = static_cast<USHORT>(procedure_name.size());
        unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;

        std::uint64_t ret;
        auto ec = call_function(ldr_procedure_address_base
                                , hmodule
                                , reinterpret_cast<std::uint64_t>(&unicode_fun_name)
                                , static_cast<std::uint64_t>(0)
                                , reinterpret_cast<std::uint64_t>(&ret));
        if (ec)
            throw std::system_error(ec, "call_function(ldr_procedure_address_base...) failed");

        return ret;
    }

    inline std::uint64_t procedure_address(std::uint64_t hmodule, const std::string& procedure_name, std::error_code& ec)
    {
        const static auto ldr_procedure_address_base = detail::ldr_procedure_address(ec);
        if (ec)
            return 0;

        definitions::UNICODE_STRING_T<std::uint64_t> unicode_fun_name;
        unicode_fun_name.Buffer = reinterpret_cast<std::uint64_t>(&procedure_name[0]);
        unicode_fun_name.Length = static_cast<USHORT>(procedure_name.size());
        unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;

        std::uint64_t ret;
        ec = call_function(ldr_procedure_address_base
                            , hmodule
                            , reinterpret_cast<std::uint64_t>(&unicode_fun_name)
                            , static_cast<std::uint64_t>(0)
                            , reinterpret_cast<std::uint64_t>(&ret));

        return ret;
    }

}

#endif // #ifndef WOW64PP_HPP
