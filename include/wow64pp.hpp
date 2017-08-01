#ifndef WOW64PP_HPP
#define WOW64PP_HPP

#include <system_error>

namespace wow64pp 
{

#include <Windows.h> // no global scope pollution
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
            DWORD Flags;
            WORD LoadCount;
            WORD TlsIndex;
            union
            {
                LIST_ENTRY_T<P> HashLinks;
                struct
                {
                    P SectionPointer;
                    P CheckSum;
                };
            };
            union
            {
                P LoadedImports;
                DWORD TimeDateStamp;
            };
            P EntryPointActivationContext;
            P PatchInformation;
            LIST_ENTRY_T<P> ForwarderLinks;
            LIST_ENTRY_T<P> ServiceTagLinks;
            LIST_ENTRY_T<P> StaticLinks;
            P ContextInformation;
            P OriginalBase;
            _LARGE_INTEGER LoadTime;
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

        inline std::uint64_t peb_address(std::error_code& ec)
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
        inline void read_memory(std::uint64_t address, P* buffer, std::size_t size = sizeof(P), std::error_code& ec)
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

    }

}

#endif // #ifndef WOW64PP_HPP
