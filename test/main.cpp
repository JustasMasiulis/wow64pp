#include <wow64pp.hpp>
#include "Catch/include/catch_with_main.hpp"



TEST_CASE("test")
{
    auto ntdll = wow64pp::module_handle("ntdll.dll");
    std::error_code ec;
    auto fn = wow64pp::import(ntdll, "NtReadVirtualMemory", ec);
    REQUIRE(!ec);
    auto h = wow64pp::detail::self_handle();

    volatile int i = 6;
    volatile int b = 20;
    std::uint64_t read;

    
    for (int idx = 0; idx < 20; ++idx) {
        read = 0;
        i = rand();
        b = rand();

        for (int j = 0; j < 200; ++j) {
            auto ret = wow64pp::call_function(fn, h, &i, &b, 4, &read);
            CHECK(ret >= 0);
            CHECK(i == b);
            REQUIRE(read == 4);
        }
    }

}