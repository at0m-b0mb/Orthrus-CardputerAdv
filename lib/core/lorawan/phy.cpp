#include "phy.h"

#include <cstring>

namespace orthrus::lorawan {
namespace {

constexpr size_t kMhdrLen = 1;
constexpr size_t kMicLen  = 4;
constexpr size_t kFhdrMinLen = 7;   // DevAddr(4) + FCtrl(1) + FCnt(2)
constexpr size_t kJoinRequestMacLen = 18;  // JoinEUI(8) + DevEUI(8) + DevNonce(2)

uint16_t rdU16LE(const uint8_t* p) {
    return static_cast<uint16_t>(p[0]) | (static_cast<uint16_t>(p[1]) << 8);
}

uint32_t rdU32LE(const uint8_t* p) {
    return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
}

// EUIs travel little-endian on the air but every datasheet, label and network
// server shows them big-endian. Reverse once, here, so nothing downstream has
// to remember which way round it is.
void rdEuiBE(const uint8_t* src, uint8_t dst[8]) {
    for (int i = 0; i < 8; i++) dst[i] = src[7 - i];
}

}  // namespace

const char* mtypeName(MType t) {
    switch (t) {
        case MType::JoinRequest:         return "JoinRequest";
        case MType::JoinAccept:          return "JoinAccept";
        case MType::UnconfirmedDataUp:   return "UnconfDataUp";
        case MType::UnconfirmedDataDown: return "UnconfDataDown";
        case MType::ConfirmedDataUp:     return "ConfDataUp";
        case MType::ConfirmedDataDown:   return "ConfDataDown";
        case MType::RejoinRequest:       return "RejoinRequest";
        case MType::Proprietary:         return "Proprietary";
    }
    return "?";
}

const char* errorName(ParseError e) {
    switch (e) {
        case ParseError::None:               return "ok";
        case ParseError::TooShort:           return "too short";
        case ParseError::BadMajor:           return "bad major";
        case ParseError::MacPayloadTooShort: return "MACPayload too short";
        case ParseError::FOptsOverrun:       return "FOptsLen overruns frame";
        case ParseError::JoinLengthWrong:    return "join length wrong";
    }
    return "?";
}

bool joinAcceptLengthIsPlausible(size_t phyLen) {
    // MHDR(1) + encrypted{AppNonce(3) NetID(3) DevAddr(4) DLSettings(1)
    // RxDelay(1) [CFList(16)]} + MIC(4) => 17 without CFList, 33 with.
    return phyLen == 17 || phyLen == 33;
}

bool parse(const uint8_t* buf, size_t len, Frame& out) {
    out = Frame{};

    if (buf == nullptr || len < kMhdrLen + kMicLen) {
        out.error = ParseError::TooShort;
        return false;
    }

    const uint8_t mhdr = buf[0];
    out.mtype = static_cast<MType>((mhdr >> 5) & 0x07);
    out.major = static_cast<uint8_t>(mhdr & 0x03);
    out.mic   = rdU32LE(buf + len - kMicLen);

    // Major 0 is the only value LoRaWAN R1 defines. Anything else is either a
    // future revision or not LoRaWAN at all; either way we must not go on to
    // interpret the layout as if it were 1.0.
    if (out.major != 0) {
        out.error = ParseError::BadMajor;
        return false;
    }

    const uint8_t* mac    = buf + kMhdrLen;
    const size_t   macLen = len - kMhdrLen - kMicLen;

    switch (out.mtype) {
        case MType::JoinRequest: {
            if (macLen != kJoinRequestMacLen) {
                out.error = ParseError::JoinLengthWrong;
                return false;
            }
            rdEuiBE(mac, out.join.joinEui);
            rdEuiBE(mac + 8, out.join.devEui);
            out.join.devNonce = rdU16LE(mac + 16);
            return true;
        }

        case MType::JoinAccept:
            // Encrypted with the AppKey. We can say it happened and how big it
            // was; we cannot say what is inside, and we will not guess.
            if (!joinAcceptLengthIsPlausible(len)) {
                out.error = ParseError::JoinLengthWrong;
                return false;
            }
            return true;

        case MType::UnconfirmedDataUp:
        case MType::UnconfirmedDataDown:
        case MType::ConfirmedDataUp:
        case MType::ConfirmedDataDown: {
            if (macLen < kFhdrMinLen) {
                out.error = ParseError::MacPayloadTooShort;
                return false;
            }

            DataFields& d = out.data;
            d.devAddr = rdU32LE(mac);

            const uint8_t fctrl = mac[4];
            d.adr      = (fctrl & 0x80) != 0;
            d.ack      = (fctrl & 0x20) != 0;
            d.fOptsLen = static_cast<uint8_t>(fctrl & 0x0F);
            if (out.isUplink()) {
                d.adrAckReq = (fctrl & 0x40) != 0;
                d.classB    = (fctrl & 0x10) != 0;
            } else {
                d.fPending = (fctrl & 0x10) != 0;
            }

            d.fCnt = rdU16LE(mac + 5);

            // FOptsLen is attacker-controlled. If it claims more bytes than the
            // frame actually carries, reject rather than reading past the end.
            const size_t fhdrLen = kFhdrMinLen + d.fOptsLen;
            if (fhdrLen > macLen) {
                out.error = ParseError::FOptsOverrun;
                return false;
            }
            d.fOpts      = d.fOptsLen ? (mac + kFhdrMinLen) : nullptr;
            d.fOptsCount = d.fOptsLen;

            const size_t remaining = macLen - fhdrLen;
            if (remaining > 0) {
                d.hasFPort = true;
                d.fPort    = mac[fhdrLen];

                const size_t frmLen = remaining - 1;
                d.frmPayload    = frmLen ? (mac + fhdrLen + 1) : nullptr;
                d.frmPayloadLen = static_cast<uint8_t>(frmLen);
            } else {
                d.hasFPort      = false;
                d.fPort         = 0;
                d.frmPayload    = nullptr;
                d.frmPayloadLen = 0;
            }
            return true;
        }

        case MType::RejoinRequest:
        case MType::Proprietary:
            // Structure is either version-dependent (rejoin) or undefined by
            // the spec (proprietary). Report the type honestly and stop.
            return true;
    }

    return true;
}

}  // namespace orthrus::lorawan
