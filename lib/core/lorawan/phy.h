// LoRaWAN PHYPayload parser.
//
// Pure: no Arduino, no allocation, no I/O. Everything here is host-testable,
// which matters because this is the one component that decides whether a
// finding is real or a lie. It parses bytes off the air that an attacker may
// have shaped deliberately, so every length is checked before it is trusted.
//
// Reference: LoRaWAN L2 1.0.4 / 1.1 specification, section 4 (MAC message
// formats). Field byte-orders are as on the air: EUIs and DevAddr are
// little-endian, which is the single most common source of bugs in third-party
// LoRaWAN decoders.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::lorawan {

// MHDR MType field (bits 7:5).
enum class MType : uint8_t {
    JoinRequest         = 0,
    JoinAccept          = 1,
    UnconfirmedDataUp   = 2,
    UnconfirmedDataDown = 3,
    ConfirmedDataUp     = 4,
    ConfirmedDataDown   = 5,
    RejoinRequest       = 6,
    Proprietary         = 7,
};

enum class ParseError : uint8_t {
    None = 0,
    TooShort,          // cannot even hold MHDR + MIC
    BadMajor,          // Major != 0; not a LoRaWAN R1 frame
    MacPayloadTooShort,// data frame without a complete FHDR
    FOptsOverrun,      // FOptsLen claims more bytes than the frame holds
    JoinLengthWrong,   // join request/accept with a non-spec length
};

struct JoinRequestFields {
    uint8_t  joinEui[8];  // aka AppEUI in 1.0.x, stored big-endian (decoded)
    uint8_t  devEui[8];   // stored big-endian (decoded)
    uint16_t devNonce;
};

struct DataFields {
    uint32_t devAddr;

    // FCtrl
    bool    adr;
    bool    adrAckReq;   // uplink only
    bool    ack;
    bool    classB;      // uplink only (RFU on downlink)
    bool    fPending;    // downlink only (RFU on uplink)
    uint8_t fOptsLen;

    uint16_t fCnt;       // lower 16 bits as transmitted

    const uint8_t* fOpts;
    uint8_t        fOptsCount;

    bool    hasFPort;
    uint8_t fPort;

    const uint8_t* frmPayload;
    uint8_t        frmPayloadLen;
};

struct Frame {
    ParseError error = ParseError::None;
    MType      mtype = MType::Proprietary;
    uint8_t    major = 0;
    uint32_t   mic   = 0;

    // Exactly one of these is meaningful, selected by mtype.
    JoinRequestFields join{};
    DataFields        data{};

    bool ok() const { return error == ParseError::None; }

    bool isJoin() const {
        return mtype == MType::JoinRequest || mtype == MType::JoinAccept;
    }
    bool isData() const {
        return mtype == MType::UnconfirmedDataUp || mtype == MType::UnconfirmedDataDown ||
               mtype == MType::ConfirmedDataUp || mtype == MType::ConfirmedDataDown;
    }
    bool isUplink() const {
        return mtype == MType::JoinRequest || mtype == MType::UnconfirmedDataUp ||
               mtype == MType::ConfirmedDataUp || mtype == MType::RejoinRequest;
    }
    bool isConfirmed() const {
        return mtype == MType::ConfirmedDataUp || mtype == MType::ConfirmedDataDown;
    }
};

// Parses a raw PHYPayload as received off the air.
//
// `buf` must remain alive for as long as `out` is read: the FOpts and
// FRMPayload members point into it rather than copying. This is deliberate --
// on a device with 359 KB of heap and no PSRAM, a parser that copies every
// frame is a parser that eventually stops working.
//
// Returns true when the frame parsed cleanly. On false, `out.error` says why,
// and every other field is left in a safe, zeroed state.
bool parse(const uint8_t* buf, size_t len, Frame& out);

// Human-readable names, for the UI and for test failure messages.
const char* mtypeName(MType t);
const char* errorName(ParseError e);

// A LoRaWAN Join Accept is encrypted with the AppKey, so without keys its
// contents are unknowable. Its *length* is still diagnostic, so expose the
// check rather than pretending we decoded it.
bool joinAcceptLengthIsPlausible(size_t phyLen);

}  // namespace orthrus::lorawan
