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

        template<typename P>
        struct PROCESS_BASIC_INFORMATION_T
        {
        private:
            P Reserved1;
        public:
            P PebBaseAddress;
        private:
            P Reserved2[2];
        public:
            P UniqueProcessId;
        private:
            P Reserved3;
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


        template<typename T>
        void read_memory(std::uint64_t address, T& buffer, std::size_t size = sizeof(T))
        {
            const auto NtWow64ReadVirtualMemory64
                = native::ntdll_function<definitions::NtWow64ReadVirtualMemory64T>("NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return;

            auto hres = NtWow64ReadVirtualMemory64(GetCurrentProcess(), address, std::addressof(buf), size, nullptr);
            detail::throw_if_failed("NtWow64ReadVirtualMemory64() failed", hres);
        }

        template<typename T>
        void read_memory(std::uint64_t address, T& buffer, std::size_t size = sizeof(T), std::error_code& ec)
        {
            const auto NtWow64ReadVirtualMemory64 
                = ntdll_function<winapi::NtWow64ReadVirtualMemory64T>("NtWow64ReadVirtualMemory64", ec);
            if (ec)
                return;

            auto hres = NtWow64ReadVirtualMemory64(_h, address, std::addressof(buf), size, nullptr);
            if (winapi::failed(hres))
                ec = get_last_error();

            return;
        }



    }

}

#endif // #ifndef WOW64PP_HPP
