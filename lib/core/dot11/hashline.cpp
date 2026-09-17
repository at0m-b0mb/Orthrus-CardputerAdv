#include "dot11/hashline.h"

#include <cstring>

namespace orthrus::dot11 {

namespace {

constexpr char kHex[] = "0123456789abcdef";

// Appends to a bounded cursor. Every writer below goes through this, so a
// single overflow check covers the whole file rather than being repeated (and
// eventually forgotten) at each field.
struct Cursor {
    char*  out  = nullptr;
    size_t cap  = 0;
    size_t used = 0;
    bool   ok   = true;

    void put(char c) {
        if (!ok) return;
        if (used + 1 >= cap) { ok = false; return; }
        out[used++] = c;
    }
    void puts(const char* s) {
        while (*s && ok) put(*s++);
    }
    void hex(const uint8_t* data, size_t len) {
        for (size_t i = 0; i < len && ok; i++) {
            put(kHex[(data[i] >> 4) & 0x0F]);
            put(kHex[data[i] & 0x0F]);
        }
    }
    size_t finish() {
        if (!ok) return 0;
        out[used] = '\0';
        return used;
    }
};

void le32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
    p[2] = static_cast<uint8_t>((v >> 16) & 0xFF);
    p[3] = static_cast<uint8_t>((v >> 24) & 0xFF);
}

void le16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v & 0xFF);
    p[1] = static_cast<uint8_t>((v >> 8) & 0xFF);
}

// The ESSID goes into the line as hex, so a name containing a star, a newline
// or a non-UTF-8 byte cannot break the format. That is not a nicety: SSIDs are
// 32 arbitrary octets chosen by whoever set up the access point.
void putEssid(Cursor& c, const char* ssid) {
    const size_t n = std::strlen(ssid);
    c.hex(reinterpret_cast<const uint8_t*>(ssid), n > kSsidMax ? kSsidMax : n);
}

}  // namespace

size_t toHex(const uint8_t* data, size_t len, char* out, size_t cap) {
    if (out == nullptr || cap == 0) return 0;
    if (len * 2 + 1 > cap) { out[0] = '\0'; return 0; }
    Cursor c{out, cap};
    c.hex(data, len);
    return c.finish();
}

size_t writePmkidLine(const Target& t, char* out, size_t cap) {
    if (out == nullptr || cap == 0) return 0;
    out[0] = '\0';
    if (!t.havePmkid) return 0;

    char ap[13], sta[13];
    formatMacBare(t.bssid, ap);
    formatMacBare(t.sta, sta);

    Cursor c{out, cap};
    c.puts("WPA*01*");
    c.hex(t.pmkid, kPmkidLen);
    c.put('*');
    c.puts(ap);
    c.put('*');
    c.puts(sta);
    c.put('*');
    putEssid(c, t.ssid);
    // The three empty fields are ANONCE, EAPOL and MESSAGEPAIR. A PMKID line
    // carries none of them, and the separators still have to be there.
    c.puts("***");

    const size_t n = c.finish();
    if (n == 0) out[0] = '\0';
    return n;
}

size_t writeEapolLine(const Target& t, char* out, size_t cap) {
    if (out == nullptr || cap == 0) return 0;
    out[0] = '\0';

    uint8_t pair = 0;
    if (!t.messagePair(pair)) return 0;
    if (t.eapolLen == 0 || !t.haveAnonce) return 0;

    char ap[13], sta[13];
    formatMacBare(t.bssid, ap);
    formatMacBare(t.sta, sta);

    Cursor c{out, cap};
    c.puts("WPA*02*");
    c.hex(t.mic, kMicLen);
    c.put('*');
    c.puts(ap);
    c.put('*');
    c.puts(sta);
    c.put('*');
    putEssid(c, t.ssid);
    c.put('*');
    c.hex(t.anonce, kNonceLen);
    c.put('*');
    c.hex(t.eapol, t.eapolLen);
    c.put('*');
    c.put(kHex[(pair >> 4) & 0x0F]);
    c.put(kHex[pair & 0x0F]);

    const size_t n = c.finish();
    if (n == 0) out[0] = '\0';
    return n;
}

size_t writePcapGlobalHeader(uint8_t* out, size_t cap, uint32_t snaplen) {
    if (out == nullptr || cap < kPcapGlobalHeaderLen) return 0;
    le32(out + 0, kPcapMagic);
    le16(out + 4, 2);   // version major
    le16(out + 6, 4);   // version minor
    le32(out + 8, 0);   // thiszone: timestamps are already UTC by convention
    le32(out + 12, 0);  // sigfigs: nobody uses it, and 0 is what tcpdump writes
    le32(out + 16, snaplen);
    le32(out + 20, kLinkTypeIeee80211);
    return kPcapGlobalHeaderLen;
}

size_t writePcapRecordHeader(uint8_t* out, size_t cap, uint32_t tsSec,
                             uint32_t tsUsec, uint32_t inclLen, uint32_t origLen) {
    if (out == nullptr || cap < kPcapRecordHeaderLen) return 0;
    // A reader that meets inclLen > origLen treats the file as corrupt from
    // that point on, so the invariant is enforced here rather than trusted.
    if (inclLen > origLen) origLen = inclLen;
    le32(out + 0, tsSec);
    le32(out + 4, tsUsec);
    le32(out + 8, inclLen);
    le32(out + 12, origLen);
    return kPcapRecordHeaderLen;
}

}  // namespace orthrus::dot11
