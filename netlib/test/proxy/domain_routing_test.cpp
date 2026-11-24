#include "pch.h"
#include "../../src/proxy/domain_routing.h"

namespace
{
    using bytes = std::vector<uint8_t>;
    using cache_t = proxy::dns_domain_cache;
    const cache_t::time_point epoch{ std::chrono::seconds(100) };
    void put16(bytes& out, uint16_t value) { out.push_back(uint8_t(value >> 8)); out.push_back(uint8_t(value)); }
    void put32(bytes& out, uint32_t value) { put16(out, uint16_t(value >> 16)); put16(out, uint16_t(value)); }
    bytes name_bytes(std::string name)
    {
        bytes out;
        for (size_t start = 0; start < name.size();)
        {
            auto end = name.find('.', start);
            if (end == std::string::npos) end = name.size();
            out.push_back(uint8_t(end - start));
            out.insert(out.end(), name.begin() + start, name.begin() + end);
            start = end + 1;
        }
        out.push_back(0); return out;
    }
    struct rr { std::string owner; uint16_t type; uint32_t ttl; bytes data; };
    bytes dns(std::string name, uint16_t type, bool response, std::vector<rr> answers = {}, uint16_t id = 0x1234)
    {
        bytes out;
        put16(out, id); put16(out, response ? 0x8180 : 0x0100); put16(out, 1);
        put16(out, uint16_t(answers.size())); put16(out, 0); put16(out, 0);
        const auto question = name_bytes(name); out.insert(out.end(), question.begin(), question.end());
        put16(out, type); put16(out, 1);
        for (const auto& answer : answers)
        {
            if (answer.owner == name) put16(out, 0xc00c);
            else { const auto owner = name_bytes(answer.owner); out.insert(out.end(), owner.begin(), owner.end()); }
            put16(out, answer.type); put16(out, 1); put32(out, answer.ttl); put16(out, uint16_t(answer.data.size()));
            out.insert(out.end(), answer.data.begin(), answer.data.end());
        }
        return out;
    }
    const bytes ip4{ 203,0,113,10 };
    std::string address4() { return proxy::domain_address_key(ip4.data(), ip4.size()); }
    void learn(cache_t& cache, std::string name, uint16_t type, std::vector<rr> answers,
        cache_t::time_point now = epoch)
    {
        const auto query = dns(name, type, false), reply = dns(name, type, true, answers);
        cache.observe_udp("client/server/port", true, query.data(), query.size(), now);
        cache.observe_udp("client/server/port", false, reply.data(), reply.size(), now);
    }
    bytes frame(const bytes& message)
    {
        bytes out; put16(out, uint16_t(message.size())); out.insert(out.end(), message.begin(), message.end()); return out;
    }
    bytes ethernet_dns(const bytes& payload, bool query, bool v6 = false, bool tcp = false,
        uint32_t sequence = 0, uint8_t flags = 0x10, bool extension = false)
    {
        bytes transport;
        put16(transport, query ? 53001 : 53); put16(transport, query ? 53 : 53001);
        if (tcp)
        {
            put32(transport, sequence); put32(transport, 0);
            transport.push_back(0x50); transport.push_back(flags);
            put16(transport, 65535); put16(transport, 0); put16(transport, 0);
        }
        else { put16(transport, uint16_t(payload.size() + 8)); put16(transport, 0); }
        transport.insert(transport.end(), payload.begin(), payload.end());
        bytes out(14 + (v6 ? 40 : 20), 0);
        out[12] = v6 ? 0x86 : 8; out[13] = v6 ? 0xdd : 0;
        const uint8_t protocol = tcp ? 6 : 17;
        if (v6)
        {
            out[14] = 0x60;
            const auto length = transport.size() + (extension ? 8 : 0);
            out[18] = uint8_t(length >> 8); out[19] = uint8_t(length);
            out[20] = extension ? 0 : protocol;
            out[22] = 0x20; out[23] = 1; out[37] = query ? 1 : 53;
            out[38] = 0x20; out[39] = 1; out[53] = query ? 53 : 1;
            if (extension) { out.push_back(protocol); out.insert(out.end(), 7, 0); }
        }
        else
        {
            out[14] = 0x45;
            const auto length = transport.size() + 20;
            out[16] = uint8_t(length >> 8); out[17] = uint8_t(length); out[23] = protocol;
            out[26] = 192; out[27] = 0; out[28] = 2; out[29] = query ? 1 : 53;
            out[30] = 192; out[31] = 0; out[32] = 2; out[33] = query ? 53 : 1;
        }
        out.insert(out.end(), transport.begin(), transport.end());
        return out;
    }
}

TEST(DomainDnsFrames, UdpLearnsIpv4AndIpv6IncludingExtensionHeader)
{
    for (const bool v6 : { false, true })
        for (const bool extension : { false, true })
        {
            cache_t cache;
            const auto query = ethernet_dns(dns("example.com",1,false),true,v6,false,0,0,extension);
            const auto reply = ethernet_dns(dns("example.com",1,true,{{"example.com",1,30,ip4}}),false,v6,false,0,0,extension);
            cache.observe_frame(query.data(),query.size(),true);
            cache.observe_frame(reply.data(),reply.size(),false);
            EXPECT_EQ(cache.lookup(address4()),std::vector<std::string>{"example.com"});
        }
}

TEST(DomainDnsFrames, TcpDnsUsesHandshakeAndReassemblesActualPacketPayloads)
{
    for (const bool v6 : { false, true })
    {
        cache_t cache;
        auto send = [&](const bytes& payload, bool query, uint32_t sequence, uint8_t flags)
        {
            const auto packet = ethernet_dns(payload,query,v6,true,sequence,flags,v6);
            cache.observe_frame(packet.data(),packet.size(),query);
        };
        send({},true,100,2); send({},false,500,0x12);
        send(frame(dns("example.com",1,false)),true,101,0x10);
        const auto reply = frame(dns("example.com",1,true,{{"example.com",1,30,ip4}}));
        send(bytes(reply.begin(),reply.begin()+1),false,501,0x10);
        send(bytes(reply.begin()+1,reply.end()),false,502,0x10);
        EXPECT_EQ(cache.lookup(address4()),std::vector<std::string>{"example.com"});
    }
}

TEST(DomainDnsFrames, TruncatedFragmentedAndNonDnsPacketsNeverLearn)
{
    const auto query = ethernet_dns(dns("example.com",1,false),true);
    const auto reply = ethernet_dns(dns("example.com",1,true,{{"example.com",1,30,ip4}}),false);
    for (size_t length = 0; length < reply.size(); ++length)
    {
        cache_t cache;
        cache.observe_frame(query.data(),query.size(),true);
        cache.observe_frame(reply.data(),length,false);
        EXPECT_TRUE(cache.lookup(address4()).empty()) << length;
    }
    for (const size_t offset : { 20u, 34u, 38u })
    {
        cache_t cache;
        auto invalid = reply;
        invalid[offset] = offset == 20 ? 0x20 : 0xff; // Fragment, source port, UDP length.
        cache.observe_frame(query.data(),query.size(),true);
        cache.observe_frame(invalid.data(),invalid.size(),false);
        EXPECT_TRUE(cache.lookup(address4()).empty());
    }
    cache_t cache;
    const auto query6 = ethernet_dns(dns("example.com",1,false),true,true);
    auto fragment6 = ethernet_dns(dns("example.com",1,true,{{"example.com",1,30,ip4}}),false,true);
    fragment6[20] = 44;
    cache.observe_frame(query6.data(),query6.size(),true);
    cache.observe_frame(fragment6.data(),fragment6.size(),false);
    EXPECT_TRUE(cache.lookup(address4()).empty());
}

TEST(DomainPatterns, ExactSuffixBoundaryAndUnknownDestination)
{
    proxy::domain_patterns rule{ {"store.example.com"}, {"steam.test"} };
    EXPECT_TRUE(rule.matches({"store.example.com"}));
    EXPECT_TRUE(rule.matches({"steam.test"}));
    EXPECT_TRUE(rule.matches({"cdn.steam.test"}));
    EXPECT_FALSE(rule.matches({"evilsteam.test"}));
    EXPECT_FALSE(rule.matches({"steam.test.evil"}));
    EXPECT_FALSE(rule.matches({}));
    EXPECT_TRUE(proxy::domain_patterns{}.matches({}));
}

TEST(DomainDnsCache, LearnsAnswerCaseInsensitivelyUntilItsTtl)
{
    cache_t cache;
    learn(cache, "Store.Example.COM", 1, {{"Store.Example.COM",1,10,ip4}});
    EXPECT_EQ(cache.lookup(address4(), epoch + std::chrono::seconds(9)), std::vector<std::string>{"store.example.com"});
    EXPECT_TRUE(cache.lookup(address4(), epoch + std::chrono::seconds(10)).empty());
}

TEST(DomainDnsCache, CnameChainUsesMinimumTtlAndOnlyRelatedAnswers)
{
    cache_t cache;
    learn(cache, "store.example.com", 1, {
        {"cdn.example.net",1,100,ip4}, {"unrelated.test",1,100,bytes{203,0,113,20}},
        {"store.example.com",5,5,name_bytes("cdn.example.net")}});
    EXPECT_EQ(cache.lookup(address4(), epoch), std::vector<std::string>{"store.example.com"});
    EXPECT_TRUE(cache.lookup(proxy::domain_address_key(bytes{203,0,113,20}.data(),4), epoch).empty());
    EXPECT_TRUE(cache.lookup(address4(), epoch + std::chrono::seconds(5)).empty());
}

TEST(DomainDnsCache, Ipv6AndIpv4MappedAddressesAreSupported)
{
    cache_t cache;
    const bytes v6{0x20,1,0x0d,0xb8,0,0,0,0,0,0,0,0,0,0,0,1};
    learn(cache, "ipv6.example", 28, {{"ipv6.example",28,30,v6}});
    EXPECT_EQ(cache.lookup(proxy::domain_address_key(v6.data(),16), epoch), std::vector<std::string>{"ipv6.example"});
    const bytes mapped{0,0,0,0,0,0,0,0,0,0,0xff,0xff,203,0,113,10};
    EXPECT_EQ(proxy::domain_address_key(mapped.data(),16), address4());
}

TEST(DomainDnsCache, UnsolicitedWrongFlowWrongIdAndWrongQuestionCannotPopulateCache)
{
    cache_t cache;
    auto query = dns("example.com",1,false), reply = dns("example.com",1,true,{{"example.com",1,30,ip4}});
    cache.observe_udp("flow",false,reply.data(),reply.size(),epoch);
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
    cache.observe_udp("flow",true,query.data(),query.size(),epoch);
    cache.observe_udp("other",false,reply.data(),reply.size(),epoch);
    auto wrong = reply; wrong[1] ^= 1;
    cache.observe_udp("flow",false,wrong.data(),wrong.size(),epoch);
    wrong = dns("evil.example",1,true,{{"evil.example",1,30,ip4}});
    cache.observe_udp("flow",false,wrong.data(),wrong.size(),epoch);
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
    cache.observe_udp("flow",false,reply.data(),reply.size(),epoch);
    EXPECT_EQ(cache.lookup(address4(),epoch), std::vector<std::string>{"example.com"});
}

TEST(DomainDnsCache, ZeroTtlAndNoDataReplaceOldBindings)
{
    cache_t cache;
    learn(cache,"example.com",1,{{"example.com",1,50,ip4}});
    learn(cache,"example.com",1,{{"example.com",1,0,ip4}});
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
    learn(cache,"example.com",1,{{"example.com",1,50,ip4}});
    learn(cache,"example.com",1,{});
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
}

TEST(DomainDnsCache, MultipleNamesForSharedIpAreRetainedAndExpireIndependently)
{
    cache_t cache;
    learn(cache,"first.example",1,{{"first.example",1,5,ip4}});
    learn(cache,"second.example",1,{{"second.example",1,20,ip4}});
    EXPECT_EQ(cache.lookup(address4(),epoch).size(),2u);
    EXPECT_EQ(cache.lookup(address4(),epoch + std::chrono::seconds(5)),std::vector<std::string>{"second.example"});
}

TEST(DomainDnsCache, EveryTruncatedResponseAndCompressionCycleIsRejectedAtomically)
{
    const auto query = dns("example.com",1,false);
    const auto reply = dns("example.com",1,true,{{"example.com",1,30,ip4}});
    for (size_t size = 0; size < reply.size(); ++size)
    {
        cache_t cache;
        cache.observe_udp("flow",true,query.data(),query.size(),epoch);
        cache.observe_udp("flow",false,reply.data(),size,epoch);
        EXPECT_TRUE(cache.lookup(address4(),epoch).empty()) << size;
    }
    cache_t cache;
    auto cycle = reply; cycle[12] = 0xc0; cycle[13] = 12;
    cache.observe_udp("flow",true,query.data(),query.size(),epoch);
    cache.observe_udp("flow",false,cycle.data(),cycle.size(),epoch);
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
}

TEST(DomainDnsCache, ExpiredTransactionsTruncationAndCnameLoopsCannotPopulateCache)
{
    cache_t cache;
    const auto query = dns("example.com",1,false);
    auto reply = dns("example.com",1,true,{{"example.com",1,30,ip4}});
    cache.observe_udp("flow",true,query.data(),query.size(),epoch);
    cache.observe_udp("flow",false,reply.data(),reply.size(),epoch + std::chrono::seconds(30));
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
    reply[2] |= 2;
    cache.observe_udp("flow",true,query.data(),query.size(),epoch);
    cache.observe_udp("flow",false,reply.data(),reply.size(),epoch);
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
    learn(cache,"example.com",1,{{"example.com",5,30,name_bytes("alias.test")},
        {"alias.test",5,30,name_bytes("example.com")},{"alias.test",1,30,ip4}});
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
}

TEST(DomainDnsCache, TcpReassemblesSplitPrefixesOutOfOrderSegmentsAndRetransmissions)
{
    cache_t cache;
    const auto query = frame(dns("example.com",1,false));
    const auto reply = frame(dns("example.com",1,true,{{"example.com",1,30,ip4}}));
    cache.observe_tcp("tcp",true,100,2,nullptr,0,epoch);
    cache.observe_tcp("tcp",false,500,0x12,nullptr,0,epoch);
    cache.observe_tcp("tcp",true,101,0x10,query.data(),1,epoch);
    cache.observe_tcp("tcp",true,102,0x10,query.data()+1,query.size()-1,epoch);
    cache.observe_tcp("tcp",false,505,0x10,reply.data()+4,reply.size()-4,epoch);
    cache.observe_tcp("tcp",false,501,0x10,reply.data(),4,epoch);
    cache.observe_tcp("tcp",false,501,0x10,reply.data(),4,epoch);
    EXPECT_EQ(cache.lookup(address4(),epoch),std::vector<std::string>{"example.com"});
}

TEST(DomainDnsCache, TcpSequenceWrapAndCoalescedMessages)
{
    cache_t cache;
    auto first = frame(dns("first.example",1,false,{},1));
    const auto second = frame(dns("second.example",1,false,{},2));
    first.insert(first.end(),second.begin(),second.end());
    const auto reply = frame(dns("second.example",1,true,{{"second.example",1,30,ip4}},2));
    cache.observe_tcp("tcp",true,0xfffffff0,2,nullptr,0,epoch);
    cache.observe_tcp("tcp",false,500,0x12,nullptr,0,epoch);
    cache.observe_tcp("tcp",true,0xfffffff1,0x10,first.data(),20,epoch);
    cache.observe_tcp("tcp",true,5,0x10,first.data()+20,first.size()-20,epoch);
    cache.observe_tcp("tcp",false,501,0x10,reply.data(),reply.size(),epoch);
    EXPECT_EQ(cache.lookup(address4(),epoch),std::vector<std::string>{"second.example"});
}

TEST(DomainDnsCache, TcpWithoutSynAndResetStreamsAreNotGuessed)
{
    cache_t cache;
    const auto query = frame(dns("example.com",1,false));
    const auto reply = frame(dns("example.com",1,true,{{"example.com",1,30,ip4}}));
    cache.observe_tcp("tcp",true,101,0x10,query.data(),query.size(),epoch);
    cache.observe_tcp("tcp",false,501,0x10,reply.data(),reply.size(),epoch);
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
    cache.observe_tcp("tcp",true,100,2,nullptr,0,epoch);
    cache.observe_tcp("tcp",true,101,4,nullptr,0,epoch);
    cache.observe_tcp("tcp",true,101,0x10,query.data(),query.size(),epoch);
    cache.observe_tcp("tcp",false,500,0x12,nullptr,0,epoch);
    cache.observe_tcp("tcp",false,501,0x10,reply.data(),reply.size(),epoch);
    EXPECT_TRUE(cache.lookup(address4(),epoch).empty());
}

TEST(DomainFlowCache, DecisionsArePerDestinationAndPinnedAcrossDnsChanges)
{
    proxy::domain_flow_cache<int> flows;
    int selected = 1;
    EXPECT_EQ(flows.choose("same socket/first destination",false,false,0,[&]{return selected;},-1,epoch),1);
    selected = 2;
    EXPECT_EQ(flows.choose("same socket/second destination",false,false,0,[&]{return selected;},-1,epoch),2);
    EXPECT_EQ(flows.choose("same socket/first destination",false,false,0,[&]{return selected;},-1,epoch),1);
    EXPECT_EQ(flows.choose("same socket/first destination",false,false,0,[&]{return selected;},-1,epoch + std::chrono::seconds(121)),2);
}

TEST(DomainFlowCache, TcpRetransmissionKeepsRouteAndPortReuseGetsNewDecision)
{
    proxy::domain_flow_cache<int> flows;
    EXPECT_EQ(flows.choose("tcp",true,true,100,[]{return 1;},-1,epoch),1);
    EXPECT_EQ(flows.choose("tcp",true,true,100,[]{return 2;},-1,epoch),1);
    EXPECT_EQ(flows.choose("tcp",true,false,0,[]{return 2;},-1,epoch),1);
    EXPECT_EQ(flows.choose("tcp",true,true,200,[]{return 2;},-1,epoch),2);
    EXPECT_EQ(flows.choose("preexisting",true,false,0,[]{return 2;},-1,epoch),0);
}

TEST(DomainRoutingPolicy, NonMatchingDestinationContinuesToFallbackButFamilyFailureStillBlocks)
{
    std::multimap<size_t,std::wstring> names{{0,L"STEAM.EXE"},{1,L"STEAM.EXE"}};
    std::vector<std::wstring> excluded;
    iphelper::network_process process{};
    process.name = L"STEAM.EXE"; process.id = 100; process.resolved = true;
    const proxy::owner_match_rules rules{names,excluded,false,2};
    auto result = proxy::select_proxy_port(rules,process,[](size_t id)
    { return proxy::proxy_route_target{true,true,uint16_t(id ? 40002 : 40001),id != 0}; });
    EXPECT_EQ(result.action,proxy::proxy_port_action::proxy); EXPECT_EQ(result.port,40002);
    result = proxy::select_proxy_port(rules,process,[](size_t)
    { return proxy::proxy_route_target{true,false,{},true}; });
    EXPECT_EQ(result.action,proxy::proxy_port_action::block);
}
