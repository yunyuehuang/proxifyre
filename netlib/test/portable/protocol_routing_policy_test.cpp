// Standalone C++20 regression test for the production routing helpers. No driver or SDK is needed.
// The owner below supplies metadata/state only; all matching and routing comes from the product header.
#include <atomic>
#include <cstdint>
#include <iostream>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace iphelper
{
    struct network_process
    {
        unsigned long id{ 1000 };
        std::wstring name{ L"STEAM.EXE" };
        std::wstring path_name{ L"C:\\STEAM\\STEAM.EXE" };
        bool resolved{ true };
        std::atomic<bool> excluded{ false }, bypass_tcp{ false }, bypass_udp{ false };
        std::optional<uint16_t> tcp_proxy_port, udp_proxy_port;
        static std::wstring to_upper(const std::wstring& value);
    };
}

#include "../../src/proxy/process_routing_policy.h"

namespace
{
    using namespace proxy;
    void check(const bool success, const char* message)
    {
        if (!success) throw std::runtime_error(message);
    }

    struct offer
    {
        bool tcp{ true }, udp{ true }, family{ true };
        uint16_t tcp_port{ 40001 }, udp_port{ 40002 };
    };

    template <owner_transport Transport, owner_family Family>
    proxy_port_result route(iphelper::network_process& owner, const std::vector<offer>& offers,
        const std::vector<std::wstring>& patterns, const std::vector<std::wstring>& excluded = {})
    {
        std::multimap<size_t, std::wstring> names;
        for (size_t i = 0; i < patterns.size(); ++i) names.emplace(i, patterns[i]);
        const owner_match_rules rules{ names, excluded, false, 2 };
        return route_owner<Transport, Family>(owner, [&]
        {
            return select_proxy_port(rules, owner, [&](const size_t index)
            {
                const auto& item = offers.at(index);
                const auto port = Transport == owner_transport::tcp ? item.tcp_port : item.udp_port;
                return proxy_route_target{
                    Transport == owner_transport::tcp ? item.tcp : item.udp, item.family,
                    port ? std::optional<uint16_t>{ port } : std::nullopt };
            });
        });
    }

    template <owner_family Family>
    void verify_family()
    {
        const offer tcp_only{ true, false, true, 41001, 41002 };
        const offer udp_only{ false, true, true, 42001, 42002 };
        for (const bool tcp_first : { true, false })
        {
            const std::vector<offer> offers = tcp_first ? std::vector<offer>{ tcp_only, udp_only }
                                                       : std::vector<offer>{ udp_only, tcp_only };
            for (const bool catch_all : { false, true })
            {
                const std::vector<std::wstring> patterns{ catch_all ? L"" : L"STEAM.EXE", L"STEAM.EXE" };
                iphelper::network_process tcp_owner, udp_owner;
                for (int packet = 0; packet < 3; ++packet)
                {
                    const auto tcp_result = route<owner_transport::tcp, Family>(tcp_owner, offers, patterns);
                    const auto udp_result = route<owner_transport::udp, Family>(udp_owner, offers, patterns);
                    check(tcp_result.action == proxy_port_action::proxy && tcp_result.port == 41001,
                        "TCP must select the TCP proxy in either rule order");
                    check(udp_result.action == proxy_port_action::proxy && udp_result.port == 42002,
                        "UDP must select the UDP proxy in either rule order");
                    check(!tcp_owner.bypass_tcp && !udp_owner.bypass_udp, "A skipped protocol must not cache bypass");
                }
            }
        }

        iphelper::network_process unmatched;
        const auto direct = route<owner_transport::udp, Family>(unmatched, { tcp_only }, { L"STEAM.EXE" });
        check(direct.action == proxy_port_action::none && unmatched.bypass_udp && !unmatched.bypass_tcp,
            "An unsupported transport must go direct after exhausting the rules");

        iphelper::network_process excluded;
        check(route<owner_transport::udp, Family>(excluded, { tcp_only, udp_only },
            { L"STEAM.EXE", L"" }, { L"STEAM" }).action == proxy_port_action::none && excluded.excluded,
            "An excluded process must never reach a later proxy");

        iphelper::network_process ordered;
        check(route<owner_transport::udp, Family>(ordered, { offer{}, udp_only },
            { L"", L"STEAM.EXE" }).port == 40002, "First match supporting the same protocol must still win");

        iphelper::network_process blocked_family;
        auto family_missing = udp_only;
        family_missing.family = false;
        check(route<owner_transport::udp, Family>(blocked_family, { family_missing, udp_only },
            { L"STEAM.EXE", L"" }).action == proxy_port_action::block,
            "Unsupported address family must still block without falling through");

        iphelper::network_process missing_listener;
        auto listener_missing = udp_only;
        listener_missing.udp_port = 0;
        check(route<owner_transport::udp, Family>(missing_listener, { listener_missing, udp_only },
            { L"STEAM.EXE", L"" }).action == proxy_port_action::block,
            "Missing listener must still block without falling through");
    }
}

int main()
{
    try
    {
        verify_family<proxy::owner_family::ipv4>();
        verify_family<proxy::owner_family::ipv6>();
        std::cout << "PASS: protocol selection, ordering, bypass cache, exclusions and blocking (IPv4/IPv6)\n";
        return 0;
    }
    catch (const std::exception& error)
    {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
