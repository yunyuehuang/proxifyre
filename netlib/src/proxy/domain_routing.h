#pragma once

// Domain routing learns only answers to observed conventional DNS queries.
// No reverse DNS, payload sniffing, or blocking resolver calls on the packet path.
#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <functional>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace proxy
{
    struct domain_patterns
    {
        std::vector<std::string> exact;
        std::vector<std::string> suffixes;

        [[nodiscard]] bool empty() const { return exact.empty() && suffixes.empty(); }
        [[nodiscard]] bool matches(const std::vector<std::string>& names) const
        {
            if (empty()) return true;
            for (const auto& name : names)
            {
                if (std::find(exact.begin(), exact.end(), name) != exact.end()) return true;
                for (const auto& suffix : suffixes)
                    if (name == suffix || (name.size() > suffix.size() &&
                        name[name.size() - suffix.size() - 1] == '.' &&
                        name.compare(name.size() - suffix.size(), suffix.size(), suffix) == 0)) return true;
            }
            return false;
        }
    };

    // Binary keys distinguish address families. IPv4-mapped IPv6 addresses use the IPv4 key.
    inline std::string domain_address_key(const void* address, const size_t size)
    {
        const auto* bytes = static_cast<const uint8_t*>(address);
        static constexpr uint8_t mapped_prefix[12]{ 0,0,0,0,0,0,0,0,0,0,0xff,0xff };
        if (size == 16 && std::memcmp(bytes, mapped_prefix, 12) == 0)
            return std::string(1, '\4') + std::string(reinterpret_cast<const char*>(bytes + 12), 4);
        return std::string(1, size == 4 ? '\4' : '\6') +
            std::string(reinterpret_cast<const char*>(bytes), size);
    }

    class dns_domain_cache
    {
    public:
        using clock = std::chrono::steady_clock;
        using time_point = clock::time_point;
        static constexpr size_t max_bindings = 16384;
        static constexpr size_t max_queries = 4096;
        static constexpr size_t max_streams = 1024;

        // Ethernet/IP decoder shared by direct replies and translated proxy replies.
        // Ignore incomplete or fragmented datagrams instead of guessing their payload.
        void observe_frame(const uint8_t* frame, size_t size, bool query)
        {
            if (size < 14) return;
            const auto* ip = frame + 14;
            const size_t captured = size - 14;
            const uint16_t ether_type = u16(frame + 12);
            const uint8_t* transport = nullptr;
            size_t length = 0;
            uint8_t protocol = 0;
            std::string source, destination;
            if (ether_type == 0x0800)
            {
                if (captured < 20 || (ip[0] >> 4) != 4) return;
                const size_t header = (ip[0] & 15) * 4, total = u16(ip + 2);
                if (header < 20 || total < header || total > captured || (u16(ip + 6) & 0x3fff)) return;
                source = domain_address_key(ip + 12, 4); destination = domain_address_key(ip + 16, 4);
                protocol = ip[9]; transport = ip + header; length = total - header;
            }
            else if (ether_type == 0x86dd)
            {
                if (captured < 40 || (ip[0] >> 4) != 6) return;
                const size_t total = 40 + u16(ip + 4);
                if (total > captured) return;
                source = domain_address_key(ip + 8, 16); destination = domain_address_key(ip + 24, 16);
                size_t offset = 40; protocol = ip[6];
                for (size_t hops = 0; protocol != 6 && protocol != 17; ++hops)
                {
                    if (hops >= 16 || offset + 2 > total) return;
                    size_t extension = 0;
                    if (protocol == 0 || protocol == 43 || protocol == 60) extension = (size_t(ip[offset + 1]) + 1) * 8;
                    else if (protocol == 51) extension = (size_t(ip[offset + 1]) + 2) * 4;
                    else return; // Includes fragments, ESP, and no-next-header.
                    if (extension > total - offset) return;
                    protocol = ip[offset]; offset += extension;
                }
                transport = ip + offset; length = total - offset;
            }
            else return;
            if ((protocol != 17 && protocol != 6) || length < 8) return;
            const uint16_t source_port = u16(transport), destination_port = u16(transport + 2);
            if ((query ? destination_port : source_port) != 53) return;
            std::string flow = query ? source + destination : destination + source;
            const uint16_t client_port = query ? source_port : destination_port;
            flow.append(reinterpret_cast<const char*>(&client_port), sizeof(client_port));
            flow += protocol == 17 ? 'U' : 'T';
            if (protocol == 17)
            {
                const size_t udp_length = u16(transport + 4);
                if (udp_length >= 8 && udp_length <= length)
                    observe_udp(flow, query, transport + 8, udp_length - 8);
            }
            else
            {
                if (length < 20) return;
                const size_t header = (transport[12] >> 4) * 4;
                if (header < 20 || header > length) return;
                observe_tcp(flow, query, u32(transport + 4), transport[13], transport + header, length - header);
            }
        }

        void clear()
        {
            std::lock_guard guard(mutex_);
            bindings_.clear(); queries_.clear(); streams_.clear(); binding_count_ = 0;
        }

        std::vector<std::string> lookup(const std::string& address, time_point now = clock::now())
        {
            std::lock_guard guard(mutex_);
            std::vector<std::string> result;
            if (const auto it = bindings_.find(address); it != bindings_.end())
                for (const auto& value : it->second)
                    if (value.expires > now && std::find(result.begin(), result.end(), value.name) == result.end())
                        result.push_back(value.name);
            return result;
        }

        void observe_udp(const std::string& flow, bool query, const uint8_t* data, size_t size,
            time_point now = clock::now())
        {
            std::lock_guard guard(mutex_);
            expire(now);
            observe_message(flow, query, data, size, now);
        }

        // TCP DNS is length-prefixed. Track both directions separately from the SYN,
        // including split prefixes/messages, retransmissions, and bounded reordering.
        void observe_tcp(const std::string& flow, bool query, uint32_t sequence, uint8_t flags,
            const uint8_t* data, size_t size, time_point now = clock::now())
        {
            std::lock_guard guard(mutex_);
            expire(now);
            const std::string key = flow + (query ? "Q" : "R");
            if (flags & 0x04) { streams_.erase(flow + "Q"); streams_.erase(flow + "R"); return; }
            if (flags & 0x02)
            {
                const auto existing = streams_.find(key);
                if (existing == streams_.end() || existing->second.initial != sequence)
                {
                    if (existing == streams_.end() && streams_.size() >= max_streams) return;
                    streams_[key] = tcp_stream{ sequence, sequence + 1, now, {}, {} };
                }
                ++sequence;
            }
            auto it = streams_.find(key);
            if (it == streams_.end()) return; // Never guess framing in an existing connection.
            auto& stream = it->second;
            stream.seen = now;
            const auto distance = static_cast<int32_t>(sequence - stream.next);
            if (distance > 0)
            {
                if (distance > 65535 || size > 65535 || stream.pending.size() >= 16)
                { streams_.erase(it); return; }
                if (size) stream.pending.emplace(sequence, std::vector<uint8_t>(data, data + size));
                return;
            }
            const auto append = [&](uint32_t seq, const uint8_t* bytes, size_t length)
            {
                const size_t skip = static_cast<uint32_t>(stream.next - seq);
                if (skip >= length) return;
                stream.buffer.insert(stream.buffer.end(), bytes + skip, bytes + length);
                stream.next += static_cast<uint32_t>(length - skip);
            };
            append(sequence, data, size);
            for (bool advanced = true; advanced;)
            {
                advanced = false;
                for (auto pending = stream.pending.begin(); pending != stream.pending.end(); ++pending)
                    if (static_cast<int32_t>(pending->first - stream.next) <= 0)
                    {
                        append(pending->first, pending->second.data(), pending->second.size());
                        stream.pending.erase(pending); advanced = true; break;
                    }
            }
            size_t consumed = 0;
            while (stream.buffer.size() - consumed >= 2)
            {
                const size_t length = u16(stream.buffer.data() + consumed);
                if (length < 12) { streams_.erase(it); return; }
                if (stream.buffer.size() - consumed - 2 < length) break;
                observe_message(flow, query, stream.buffer.data() + consumed + 2, length, now);
                consumed += 2 + length;
            }
            stream.buffer.erase(stream.buffer.begin(), stream.buffer.begin() + consumed);
            if (stream.buffer.size() > 65537 || (flags & 0x01)) streams_.erase(it);
        }

    private:
        struct binding { std::string name; uint16_t type; time_point expires; };
        struct question { std::string name; uint16_t type; time_point expires; };
        struct record { std::string name; uint16_t type; uint32_t ttl; std::string value; };
        struct message
        {
            uint16_t id{}, type{};
            bool response{};
            std::string name;
            std::vector<record> answers;
        };
        struct tcp_stream
        {
            uint32_t initial{}, next{};
            time_point seen;
            std::vector<uint8_t> buffer;
            std::map<uint32_t, std::vector<uint8_t>> pending;
        };
        std::mutex mutex_;
        std::unordered_map<std::string, std::vector<binding>> bindings_;
        std::unordered_map<std::string, question> queries_;
        std::unordered_map<std::string, tcp_stream> streams_;
        size_t binding_count_{};

        static uint16_t u16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
        static uint32_t u32(const uint8_t* p) { return (uint32_t(u16(p)) << 16) | u16(p + 2); }

        static bool read_name(const uint8_t* data, size_t size, size_t& cursor, std::string& name)
        {
            size_t at = cursor;
            bool jumped = false;
            for (size_t hops = 0; hops < 128 && at < size; ++hops)
            {
                const uint8_t length = data[at++];
                if ((length & 0xc0) == 0xc0)
                {
                    if (at >= size) return false;
                    const size_t target = ((length & 0x3f) << 8) | data[at++];
                    if (target >= at - 2) return false; // Compression references prior labels only.
                    if (!jumped) cursor = at;
                    jumped = true; at = target; continue;
                }
                if (length & 0xc0 || length > 63 || at + length > size) return false;
                if (!length) { if (!jumped) cursor = at; return !name.empty(); }
                if (!name.empty()) name += '.';
                for (size_t i = 0; i < length; ++i)
                {
                    unsigned char ch = data[at++];
                    if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                        (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')) return false;
                    name += ch >= 'A' && ch <= 'Z' ? char(ch + ('a' - 'A')) : char(ch);
                }
                if (name.size() > 253) return false;
            }
            return false;
        }

        static std::optional<message> parse(const uint8_t* data, size_t size)
        {
            if (size < 12 || size > 65535 || u16(data + 4) != 1) return {};
            const uint16_t flags = u16(data + 2);
            if ((flags & 0x7800) || (flags & 0x0200) || (flags & 0x000f)) return {};
            message result;
            result.id = u16(data); result.response = (flags & 0x8000) != 0;
            size_t offset = 12;
            if (!read_name(data, size, offset, result.name) || offset + 4 > size) return {};
            result.type = u16(data + offset);
            if ((result.type != 1 && result.type != 28) || u16(data + offset + 2) != 1) return {};
            offset += 4;
            const size_t answers = u16(data + 6);
            if (answers > 256) return {};
            for (size_t i = 0; i < answers; ++i)
            {
                record value{};
                if (!read_name(data, size, offset, value.name) || offset + 10 > size) return {};
                value.type = u16(data + offset);
                const auto klass = u16(data + offset + 2);
                value.ttl = u32(data + offset + 4);
                const size_t length = u16(data + offset + 8);
                offset += 10;
                if (length > size - offset) return {};
                if (klass == 1)
                {
                    if ((value.type == 1 && length == 4) || (value.type == 28 && length == 16))
                        value.value = domain_address_key(data + offset, length);
                    else if (value.type == 5)
                    {
                        size_t end = offset;
                        if (!read_name(data, size, end, value.value) || end != offset + length) return {};
                    }
                    else { offset += length; continue; }
                    result.answers.push_back(std::move(value));
                }
                offset += length;
            }
            return result;
        }

        void expire(time_point now)
        {
            for (auto it = queries_.begin(); it != queries_.end();)
                if (it->second.expires <= now) it = queries_.erase(it); else ++it;
            for (auto it = streams_.begin(); it != streams_.end();)
                if (now - it->second.seen > std::chrono::seconds(30)) it = streams_.erase(it); else ++it;
            for (auto it = bindings_.begin(); it != bindings_.end();)
            {
                auto& values = it->second;
                const size_t before = values.size();
                std::erase_if(values, [&](const binding& b) { return b.expires <= now; });
                binding_count_ -= before - values.size();
                if (values.empty()) it = bindings_.erase(it); else ++it;
            }
        }

        void observe_message(const std::string& flow, bool query, const uint8_t* data, size_t size, time_point now)
        {
            const auto parsed = parse(data, size);
            if (!parsed || parsed->response == query) return;
            const auto& msg = *parsed;
            const std::string key = flow + char(msg.id >> 8) + char(msg.id & 0xff);
            if (query)
            {
                if (queries_.size() < max_queries || queries_.contains(key))
                    queries_[key] = { msg.name, msg.type, now + std::chrono::seconds(30) };
                return;
            }
            const auto pending = queries_.find(key);
            if (pending == queries_.end() || pending->second.name != msg.name || pending->second.type != msg.type) return;
            queries_.erase(pending);

            std::string current = msg.name;
            uint32_t ttl = 86400; // Cap retention, never extend the DNS TTL.
            std::vector<std::pair<std::string, uint32_t>> learned;
            std::vector<std::string> visited;
            for (size_t hop = 0; hop < 16; ++hop)
            {
                if (std::find(visited.begin(), visited.end(), current) != visited.end()) return;
                visited.push_back(current);
                for (const auto& answer : msg.answers)
                    if (answer.name == current && answer.type == msg.type && !answer.value.empty())
                        learned.emplace_back(answer.value, (std::min)(ttl, answer.ttl));
                const auto alias = std::find_if(msg.answers.begin(), msg.answers.end(),
                    [&](const record& r) { return r.name == current && r.type == 5; });
                if (alias == msg.answers.end()) break;
                ttl = (std::min)(ttl, alias->ttl); current = alias->value;
                if (hop == 15) return;
            }
            // A fresh answer replaces this question/type's previous records, including TTL=0/NODATA.
            for (auto it = bindings_.begin(); it != bindings_.end();)
            {
                auto& values = it->second;
                const size_t before = values.size();
                std::erase_if(values, [&](const binding& b) { return b.name == msg.name && b.type == msg.type; });
                binding_count_ -= before - values.size();
                if (values.empty()) it = bindings_.erase(it); else ++it;
            }
            for (const auto& [address, lifetime] : learned)
                if (lifetime && binding_count_ < max_bindings)
                {
                    auto& values = bindings_[address];
                    if (values.size() < 64)
                    { values.push_back({ msg.name, msg.type, now + std::chrono::seconds(lifetime) }); ++binding_count_; }
                }
        }
    };

    // Keep a decision (including direct/block) for each destination, not for a UDP
    // socket as a whole. DNS expiry affects new flows; it cannot move a live flow.
    template <typename Result>
    class domain_flow_cache
    {
        using clock = std::chrono::steady_clock;
        struct entry { Result result; clock::time_point seen; uint32_t initial; bool tcp; };
        std::mutex mutex_;
        std::unordered_map<std::string, entry> entries_;
        clock::time_point next_sweep_{};
    public:
        void clear() { std::lock_guard guard(mutex_); entries_.clear(); next_sweep_ = {}; }

        template <typename Select>
        Result choose(const std::string& key, bool tcp, bool syn, uint32_t initial, Select&& select,
            const Result& capacity_result, clock::time_point now = clock::now())
        {
            std::lock_guard guard(mutex_);
            if (now >= next_sweep_)
            {
                std::erase_if(entries_, [&](const auto& pair)
                { return now - pair.second.seen > (pair.second.tcp ? std::chrono::seconds(7200) : std::chrono::seconds(120)); });
                next_sweep_ = now + std::chrono::seconds(30);
            }
            auto existing = entries_.find(key);
            if (existing != entries_.end())
            {
                const auto idle = existing->second.tcp ? std::chrono::seconds(7200) : std::chrono::seconds(120);
                if (now - existing->second.seen <= idle && (!tcp || !syn || initial == existing->second.initial))
                { existing->second.seen = now; return existing->second.result; }
                entries_.erase(existing);
            }
            if (tcp && !syn) return {}; // Connection predates observation: leave it alone.
            if (entries_.size() >= 32768) return capacity_result;
            const Result result = select();
            entries_.emplace(key, entry{ result, now, initial, tcp });
            return result;
        }
    };
}
