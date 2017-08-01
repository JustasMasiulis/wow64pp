#ifndef WOW64PP_HPP
#define WOW64PP_HPP

#include <system_error>
#include <vector>

namespace wow64pp 
{

// no global scope pollution
#include <Windows.h> 
#include <winternl.h>

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

    }


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
            DWORD Length;
            DWORD Initialized;
            P SsHandle;
            LIST_ENTRY_T<P> InLoadOrderModuleList;
            LIST_ENTRY_T<P> InMemoryOrderModuleList;
            LIST_ENTRY_T<P> InInitializationOrderModuleList;
            P EntryInProgress;
            DWORD ShutdownInProgress;
            P ShutdownThreadId;
        };


        template<typename P>
        struct UNICODE_STRING_T {
            USHORT Length;
            USHORT MaximumLength;
            P  Buffer;
        };


        template <class P>
        struct LDR_DATA_TABLE_ENTRY_T
        {
            LIST_ENTRY_T<P> InLoadOrderLinks;
            LIST_ENTRY_T<P> InMemoryOrderLinks;
            LIST_ENTRY_T<P> InInitializationOrderLinks;
            P DllBase;
            P EntryPoint;
            union
            {
                DWORD SizeOfImage;
                P dummy01;
            };
            UNICODE_STRING_T<P> FullDllName;
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


        using RtlSetLastWin32ErrorT = ULONG(WINAPI *)(NTSTATUS);


        enum registers
        {
            _RAX = 0,
            _RCX = 1,
            _RDX = 2,
            _RBX = 3,
            _RSP = 4,
            _RBP = 5,
            _RSI = 6,
            _RDI = 7,
            _R8 = 8,
            _R9 = 9,
            _R10 = 10,
            _R11 = 11,
            _R12 = 12,
            _R13 = 13,
            _R14 = 14,
            _R15 = 15
        };


        union reg64 
        {
            DWORD64 v;
            DWORD   dw[2];
        };


#define EMIT(a) __asm __emit (a)

#define X64_Start_with_CS(_cs) \
    { \
    EMIT(0x6A) EMIT(_cs)                         /*  push   _cs             */ \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)   /*  call   $+5             */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(5)        /*  add    dword [esp], 5  */ \
    EMIT(0xCB)                                   /*  retf                   */ \
    }

#define X64_End_with_CS(_cs) \
    { \
    EMIT(0xE8) EMIT(0) EMIT(0) EMIT(0) EMIT(0)                                 /*  call   $+5                   */ \
    EMIT(0xC7) EMIT(0x44) EMIT(0x24) EMIT(4) EMIT(_cs) EMIT(0) EMIT(0) EMIT(0) /*  mov    dword [rsp + 4], _cs  */ \
    EMIT(0x83) EMIT(4) EMIT(0x24) EMIT(0xD)                                    /*  add    dword [rsp], 0xD      */ \
    EMIT(0xCB)                                                                 /*  retf                         */ \
    }

#define X64_Pop(r) EMIT(0x48 | ((r) >> 3)) EMIT(0x58 | ((r) & 7))

#define REX_W EMIT(0x48) __asm

    }


    namespace native 
    {

        inline HMODULE module_address(const char* name)
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                detail::throw_last_error("GetModuleHandleA  returned NULL");

            return addr;
        }

        inline HMODULE module_address(const char* name, std::error_code& ec) noexcept
        {
            const auto addr = GetModuleHandleA(name);
            if (addr == nullptr)
                ec = detail::get_last_error();

            return addr;
        }


        template <typename F>
        inline F ntdll_function(const char* name)
        {
            const static auto ntdll_addr = module_address("ntdll.dll");
            auto f = reinterpret_cast<F>(GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                detail::throw_last_error("failed to get address of ntdll function" + std::string(name));

            return f;
        }

        template <typename F>
        inline F ntdll_function(const char* name, std::error_code& ec) noexcept
        {
            const auto ntdll_addr = module_address("ntdll.dll", ec);
            if (ec)
                return nullptr;

            const auto f = reinterpret_cast<F>(GetProcAddress(ntdll_addr, name));

            if (f == nullptr)
                ec = detail::get_last_error();

            return f;
        }

    }


    namespace x64 
    {

        inline std::uint64_t peb_address()
        {
            const static auto NtWow64QueryInformationProcess64
                = native::ntdll_function<definitions::NtQueryInformationProcessT>("NtWow64QueryInformationProcess64");

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
                = native::ntdll_function<definitions::NtQueryInformationProcessT>("NtWow64QueryInformationProcess64", ec);
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
            const auto NtWow64ReadVirtualMemory64
                = native::ntdll_function<definitions::NtWow64ReadVirtualMemory64T>("NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return;

            auto hres = NtWow64ReadVirtualMemory64(GetCurrentProcess(), address, buffer, size, nullptr);
            detail::throw_if_failed("NtWow64ReadVirtualMemory64() failed", hres);
        }

        template<typename P>
        inline void read_memory(std::uint64_t address, P* buffer, std::size_t size = sizeof(P), std::error_code& ec) noexcept
        {
            const auto NtWow64ReadVirtualMemory64 
                = native::ntdll_function<winapi::NtWow64ReadVirtualMemory64T>("NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return;

            auto hres = NtWow64ReadVirtualMemory64(_h, address, buffer, size, nullptr);
            if (FAILED(hres))
                ec = detail::get_last_error();

            return;
        }


        inline std::uint64_t module_handle(const std::string& module_name)
        {
            definitions::PEB_T<std::uint64_t> peb64;
            read_memory(peb_address(), &peb64, sizeof(peb64));

            definitions::PEB_LDR_DATA_T<std::uint64_t> ldr;
            read_memory(peb64.Ldr, &ldr, sizeof(ldr));

            const auto last_entry = peb64.Ldr
                + offsetof(definitions::PEB_LDR_DATA_T<std::uint64_t>, InLoadOrderModuleList);

            definitions::LDR_DATA_TABLE_ENTRY_T<std::uint64_t> head;
            head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;

            do {
                read_memory(head.InLoadOrderLinks.Flink, &head, sizeof(head));

                auto other_module_name_len = head.BaseDllName.Length / sizeof(wchar_t);
                if (other_module_name_len != module_name.length())
                    continue;

                std::wstring other_module_name;
                other_module_name.resize(other_module_name_len);
                read_memory(head.BaseDllName.Buffer, &other_module_name[0], head.BaseDllName.Length);

                if (std::equal(begin(module_name), end(module_name), begin(other_module_name)))
                    return head.DllBase;
            } while (head.InLoadOrderLinks.Flink != last_entry);

            throw std::system_error(std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category())
                                    , "Could not get x64 module handle");
        }

        inline std::uint64_t module_handle(const std::string& module_name, std::error_code& ec)
        {
            definitions::PEB_T<std::uint64_t> peb64;
            {
                const auto peb_addr = peb_address(ec);
                if (ec)
                    return 0;

                read_memory(peb_addr, &peb64, sizeof(peb64), ec);

                if (ec)
                    return 0;
            }

            definitions::PEB_LDR_DATA_T<std::uint64_t> ldr;
            read_memory(peb64.Ldr, &ldr, sizeof(ldr), ec);
            if (ec)
                return 0;

            const auto last_entry = peb64.Ldr
                + offsetof(definitions::PEB_LDR_DATA_T<std::uint64_t>, InLoadOrderModuleList);

            definitions::LDR_DATA_TABLE_ENTRY_T<std::uint64_t> head;
            head.InLoadOrderLinks.Flink = ldr.InLoadOrderModuleList.Flink;

            do {
                read_memory(head.InLoadOrderLinks.Flink, &head, sizeof(head), ec);
                if (ec)
                    continue;

                auto other_module_name_len = head.BaseDllName.Length / sizeof(wchar_t);
                if (other_module_name_len != module_name.length())
                    continue;

                std::wstring other_module_name;
                other_module_name.resize(other_module_name_len);
                read_memory(head.BaseDllName.Buffer, &other_module_name[0], head.BaseDllName.Length, ec);
                if (ec)
                    continue;

                if (std::equal(begin(module_name), end(module_name), begin(other_module_name)))
                    return head.DllBase;

            } while (head.InLoadOrderLinks.Flink != last_entry);

            if (!ec)
                ec = std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category());
        }


        inline IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base)
        {
            IMAGE_DOS_HEADER idh;
            read_memory(ntdll_base, &idh, sizeof(IMAGE_DOS_HEADER));

            IMAGE_NT_HEADERS64 inh;
            read_memory(ntdll_base + idh.e_lfanew, &inh, sizeof(IMAGE_NT_HEADERS64));

            const auto idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (idd.VirtualAddress == 0)
                throw std::runtime_error("IMAGE_EXPORT_DIRECTORY::VirtualAddress was 0");

            IMAGE_EXPORT_DIRECTORY ied;
            read_memory(ntdll_base + idd.VirtualAddress, &ied, sizeof(IMAGE_EXPORT_DIRECTORY));

            return ied;
        }

        inline IMAGE_EXPORT_DIRECTORY image_export_dir(std::uint64_t ntdll_base, std::error_code& ec) noexcept
        {
            IMAGE_DOS_HEADER idh;
            read_memory(ntdll_base, &idh, sizeof(IMAGE_DOS_HEADER), ec);
            if (ec)
                return {};

            IMAGE_NT_HEADERS64 inh;
            read_memory(ntdll_base + idh.e_lfanew, &inh, sizeof(IMAGE_NT_HEADERS64), ec);
            if (ec)
                return {};

            const auto idd = inh.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

            if (idd.VirtualAddress == 0) {
                ec = std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category());
                return {};
            }
                

            IMAGE_EXPORT_DIRECTORY ied;
            read_memory(ntdll_base + idd.VirtualAddress, &ied, sizeof(IMAGE_EXPORT_DIRECTORY), ec);

            return ied;
        }


        inline std::uint64_t ldr_procedure_address()
        {
            const static auto ntdll_base = module_handle("ntdll.dll");

            auto ied = image_export_dir(ntdll_base);

            std::vector<DWORD> rva_table(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfFunctions, rva_table.data(), sizeof(DWORD) * ied.NumberOfFunctions);

            std::vector<WORD> ord_table(ied.NumberOfFunctions);
            read_memory(ntdll_base + ied.AddressOfNameOrdinals, ord_table.data(), sizeof(WORD) * ied.NumberOfFunctions);

            std::vector<DWORD> name_table(ied.NumberOfNames);
            read_memory(ntdll_base + ied.AddressOfNames, name_table.data(), sizeof(DWORD) * ied.NumberOfNames);

            std::string buffer;
            buffer.resize(sizeof("LdrGetProcedureAddress"));

            for (std::size_t i = 0; i < ied.NumberOfFunctions; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size());

                if (buffer == "LdrGetProcedureAddress")
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

            auto ied = image_export_dir(ntdll_base, ec);
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

            std::string buffer;
            buffer.resize(sizeof("LdrGetProcedureAddress"));

            for (std::size_t i = 0; i < ied.NumberOfFunctions; ++i) {
                read_memory(ntdll_base + name_table[i], &buffer[0], buffer.size(), ec);
                if (ec)
                    continue;

                if (buffer == "LdrGetProcedureAddress")
                    return ntdll_base + rva_table[ord_table[i]];
            }

            ec = std::error_code(STATUS_ORDINAL_NOT_FOUND, std::system_category());
            return 0;
        }


#pragma warning(push)
#pragma warning(disable : 4409) // illegal instruction size
        inline std::error_code __cdecl call_function(std::uint64_t func, int argC, ...)
        {
            va_list args;
            va_start(args, argC);
            definitions::reg64 _rcx = { (argC > 0) ? argC-- , va_arg(args, std::uint64_t) : 0 };
            definitions::reg64 _rdx = { (argC > 0) ? argC-- , va_arg(args, std::uint64_t) : 0 };
            definitions::reg64 _r8 = { (argC > 0) ? argC-- , va_arg(args, std::uint64_t) : 0 };
            definitions::reg64 _r9 = { (argC > 0) ? argC-- , va_arg(args, std::uint64_t) : 0 };
            definitions::reg64 _rax = { 0 };

            definitions::reg64 restArgs = { reinterpret_cast<uint64_t>(&va_arg(args, std::uint64_t)) };

            // conversion to QWORD for easier use in inline assembly
            definitions::reg64 _argC = { static_cast<uint64_t>(argC) };
            DWORD back_esp = 0;
            WORD back_fs = 0;

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

                    X64_Start_with_CS(0x33)

                ;// below code is compiled as x86 inline asm, but it is executed as x64 code
                ;// that's why it need sometimes REX_W() macro, right column contains detailed
                ;// transcription how it will be interpreted by CPU

                ;// fill first four arguments
                REX_W mov ecx, _rcx.dw[0];// mov     rcx, qword ptr [_rcx]
                REX_W mov edx, _rdx.dw[0];// mov     rdx, qword ptr [_rdx]
                push _r8.v;// push    qword ptr [_r8]
                X64_Pop(_R8); ;// pop     r8
                push _r9.v;// push    qword ptr [_r9]
                X64_Pop(_R9); ;// pop     r9
                ;//
                REX_W mov eax, _argC.dw[0];// mov     rax, qword ptr [_argC]
                ;// 
                ;// final stack adjustment, according to the    ;//
                ;// number of arguments above 4                 ;// 
                test al, 1;// test    al, 1
                jnz _no_adjust;// jnz     _no_adjust
                sub esp, 8;// sub     rsp, 8
            _no_adjust:;//
                ;// 
                push edi;// push    rdi
                REX_W mov edi, restArgs.dw[0];// mov     rdi, qword ptr [restArgs]
                ;// 
                ;// put rest of arguments on the stack          ;// 
                REX_W test eax, eax;// test    rax, rax
                jz _ls_e;// je      _ls_e
                REX_W lea edi, dword ptr[edi + 8 * eax - 8];// lea     rdi, [rdi + rax*8 - 8]
                ;// 
            _ls:;// 
                REX_W test eax, eax;// test    rax, rax
                jz _ls_e;// je      _ls_e
                push dword ptr[edi];// push    qword ptr [rdi]
                REX_W sub edi, 8;// sub     rdi, 8
                REX_W sub eax, 1;// sub     rax, 1
                jmp _ls;// jmp     _ls
            _ls_e:;// 
                ;// 
                ;// create stack space for spilling registers   ;// 
                REX_W sub esp, 0x20;// sub     rsp, 20h
                ;// 
                call func;// call    qword ptr [func]
                ;// 
                ;// cleanup stack                               ;// 
                REX_W mov ecx, _argC.dw[0];// mov     rcx, qword ptr [_argC]
                REX_W lea esp, dword ptr[esp + 8 * ecx + 0x20];// lea     rsp, [rsp + rcx*8 + 20h]
                ;// 
                pop edi;// pop     rdi
                ;// 
                 // set return value                             ;// 
                REX_W mov _rax.dw[0], eax;// mov     qword ptr [_rax], rax

                X64_End_with_CS(0x23)

                mov ax, ds
                    mov ss, ax
                    mov esp, back_esp

                    ;// restore FS segment
                mov ax, back_fs
                    mov fs, ax
            }

            return (_rax.v == 0
                ? std::error_code()
                : std::error_code(RtlNtStatusToDosError(static_cast<NTSTATUS>(_rax.v)), std::system_category()));
        }
#pragma warning(pop)


        inline std::uint64_t procedure_address(std::uint64_t hmodule, const std::string& procedure_name)
        {
            const static auto ldr_procedure_address_base = ldr_procedure_address();

            definitions::UNICODE_STRING_T<std::uint64_t> unicode_fun_name;
            unicode_fun_name.Buffer = reinterpret_cast<uint64_t>(&procedure_name[0]);
            unicode_fun_name.Length = static_cast<USHORT>(procedure_name.size());
            unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;

            std::uint64_t ret;
            auto ec = call_function(ldr_procedure_address_base
                     , 4
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
            const static auto ldr_procedure_address_base = ldr_procedure_address();

            definitions::UNICODE_STRING_T<std::uint64_t> unicode_fun_name;
            unicode_fun_name.Buffer = reinterpret_cast<uint64_t>(&procedure_name[0]);
            unicode_fun_name.Length = static_cast<USHORT>(procedure_name.size());
            unicode_fun_name.MaximumLength = unicode_fun_name.Length + 1;

            std::uint64_t ret;
            ec = call_function(ldr_procedure_address_base
                               , 4
                               , hmodule
                               , reinterpret_cast<std::uint64_t>(&unicode_fun_name)
                               , static_cast<std::uint64_t>(0)
                               , reinterpret_cast<std::uint64_t>(&ret));

            return ret;
        }

    }

}

#endif // #ifndef WOW64PP_HPP
