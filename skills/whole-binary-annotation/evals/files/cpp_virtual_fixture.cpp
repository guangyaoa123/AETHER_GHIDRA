#include <cstdint>
#include <cstring>

namespace fixture {

struct Packet {
    const std::uint8_t *data;
    std::uint32_t length;
    std::uint32_t cursor;
    bool valid;
};

class Parser {
public:
    virtual ~Parser() = default;
    virtual int parse(Packet *packet) = 0;
    virtual void reset(Packet *packet) { packet->cursor = 0; packet->valid = true; }
};

class MessageParser final : public Parser {
public:
    int parse(Packet *packet) override {
        if (packet == nullptr || packet->data == nullptr || packet->length < 4) {
            return -1;
        }
        packet->cursor = 4;
        packet->valid = std::memcmp(packet->data, "MSG!", 4) == 0;
        return packet->valid ? static_cast<int>(packet->length - packet->cursor) : -2;
    }
};

__attribute__((noinline)) int dispatch(Parser *parser, Packet *packet) {
    parser->reset(packet);
    return parser->parse(packet);
}

} // namespace fixture

int main(int argc, char **argv) {
    const auto *bytes = reinterpret_cast<const std::uint8_t *>(argc > 1 ? argv[1] : "BAD");
    fixture::Packet packet{bytes, static_cast<std::uint32_t>(std::strlen(reinterpret_cast<const char *>(bytes))), 0, false};
    fixture::MessageParser parser;
    return fixture::dispatch(&parser, &packet);
}
