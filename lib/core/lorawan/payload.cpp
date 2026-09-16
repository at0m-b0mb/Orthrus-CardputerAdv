#include "payload.h"

namespace orthrus::lorawan {
namespace {

bool isPrintable(uint8_t b) {
    return (b >= 0x20 && b <= 0x7E) || b == '\r' || b == '\n' || b == '\t';
}

// Confidence for an all-printable run of n bytes.
//
// False-positive probability is 0.371^n. Rather than invent numbers, each tier
// below is the length at which that probability crosses a decade:
//   n =  8 -> 3.6e-4      n = 12 -> 6.8e-6      n = 16 -> 1.3e-7
// Capped at 95: a passive listener without keys can never be certain, and a
// tool that prints 100% confidence about something it cannot verify is lying.
uint8_t printableConfidence(uint8_t n) {
    if (n >= 16) return 95;
    if (n >= 12) return 90;
    if (n >= kMinPlaintextLen) return 80;
    return 0;
}

}  // namespace

const char* payloadSignalName(PayloadSignal s) {
    switch (s) {
        case PayloadSignal::NoEvidence:     return "no evidence";
        case PayloadSignal::PrintableText:  return "printable text";
        case PayloadSignal::StructuredText: return "structured text";
        case PayloadSignal::LowDiversity:   return "low diversity";
    }
    return "?";
}

PayloadVerdict inspectPayload(const uint8_t* payload, uint8_t len) {
    PayloadVerdict v;
    if (payload == nullptr || len < kMinPlaintextLen) return v;

    uint8_t printable = 0;
    bool seen[256]    = {false};
    uint16_t distinct = 0;

    bool hasBrace = false, hasQuoteOrColon = false, hasCloseBrace = false;
    bool hasComma = false, hasDigit = false;

    for (uint8_t i = 0; i < len; i++) {
        const uint8_t b = payload[i];
        if (isPrintable(b)) printable++;
        if (!seen[b]) {
            seen[b] = true;
            distinct++;
        }
        if (b == '{') hasBrace = true;
        if (b == '}') hasCloseBrace = true;
        if (b == '"' || b == ':') hasQuoteOrColon = true;
        if (b == ',') hasComma = true;
        if (b >= '0' && b <= '9') hasDigit = true;
    }

    const bool allPrintable = (printable == len);

    if (allPrintable && hasBrace && hasCloseBrace && hasQuoteOrColon) {
        v.signal     = PayloadSignal::StructuredText;
        v.confidence = 97;
        v.reason     = "JSON in cleartext";
        return v;
    }

    if (allPrintable && hasComma && hasDigit && len >= 12) {
        v.signal     = PayloadSignal::StructuredText;
        v.confidence = 92;
        v.reason     = "delimited values in cleartext";
        return v;
    }

    if (allPrintable) {
        v.signal     = PayloadSignal::PrintableText;
        v.confidence = printableConfidence(len);
        v.reason     = "all bytes printable ASCII";
        return v;
    }

    // Ciphertext of n bytes should show close to min(n, 256) distinct values.
    // Very low diversity means the payload is padding, a counter, or a stuck
    // sensor -- not AES output. Weaker evidence than printable text, so it is
    // scored lower and only considered once there is enough of it to mean
    // anything.
    if (len >= 16 && distinct <= 3) {
        v.signal     = PayloadSignal::LowDiversity;
        v.confidence = 70;
        v.reason     = "too few distinct bytes for ciphertext";
        return v;
    }

    return v;
}

}  // namespace orthrus::lorawan
