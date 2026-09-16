// Host tests for SHA-256 and the evidence chain.
//
// The hash is checked against the FIPS 180-4 vectors, including the
// million-character one, because a hand-written hash that is subtly wrong is
// worse than no hash: it produces confident digests that verify against nothing
// else in the world.
//
// The chain tests are mostly about tampering, including one that proves the
// limitation the header admits to -- an attacker who rewrites the whole file
// passes the internal check and is caught only by a head recorded elsewhere.

#include <unity.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "crypto/sha256.h"
#include "evidence/chain.h"

using namespace orthrus::crypto;
using namespace orthrus::evidence;

namespace {

std::string hexOf(const void* data, size_t len) {
    uint8_t d[kSha256DigestLen];
    sha256(data, len, d);
    char hex[65];
    toHex(d, hex);
    return std::string(hex);
}

Record makeRecord(uint32_t seq, RecordKind kind, const char* detail) {
    Record r;
    r.seq    = seq;
    r.timeMs = 1000 * seq;
    r.kind   = kind;
    std::snprintf(r.detail, kDetailLen, "%s", detail);
    return r;
}

// Builds a small, realistic log and its digests.
struct Log {
    std::vector<Record> records;
    std::vector<std::array<uint8_t, kSha256DigestLen>> digests;
    uint8_t head[kSha256DigestLen]{};
};

const char kSeed[] = "orthrus-session-2026-09-16T14:00Z";

Log buildLog() {
    Log log;
    Chain chain;
    chain.begin(kSeed, sizeof(kSeed));

    const Record rs[] = {
        makeRecord(0, RecordKind::SessionStart, "EU868 survey, site A"),
        makeRecord(1, RecordKind::Device, "26011BDA rssi -78 frames 14"),
        makeRecord(2, RecordKind::Finding, "26011BDA payload-not-encrypted 97"),
        makeRecord(3, RecordKind::Device, "260ABCDE rssi -101 frames 11"),
        makeRecord(4, RecordKind::Finding, "260ABCDE fcnt-reset 95"),
        makeRecord(5, RecordKind::SessionEnd, "6 devices, 33 percent coverage"),
    };

    for (const auto& r : rs) {
        std::array<uint8_t, kSha256DigestLen> d{};
        chain.append(r, d.data());
        log.records.push_back(r);
        log.digests.push_back(d);
    }
    std::memcpy(log.head, chain.head(), kSha256DigestLen);
    return log;
}

VerifyReport verifyLog(const Log& log, const uint8_t* expectedHead = nullptr) {
    return verify(log.records.data(),
                  reinterpret_cast<const uint8_t(*)[kSha256DigestLen]>(
                      log.digests.data()),
                  log.records.size(), kSeed, sizeof(kSeed), expectedHead);
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- SHA-256 against the published vectors ----------------------------------

void test_sha256_empty_string() {
    TEST_ASSERT_EQUAL_STRING(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        hexOf("", 0).c_str());
}

void test_sha256_abc() {
    TEST_ASSERT_EQUAL_STRING(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        hexOf("abc", 3).c_str());
}

void test_sha256_448_bit_message() {
    const char* s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    TEST_ASSERT_EQUAL_STRING(
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        hexOf(s, std::strlen(s)).c_str());
}

void test_sha256_896_bit_message() {
    const char* s =
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
        "ijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    TEST_ASSERT_EQUAL_STRING(
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1",
        hexOf(s, std::strlen(s)).c_str());
}

void test_sha256_one_million_a() {
    // The vector that catches length-counter and padding bugs.
    std::string s(1000000, 'a');
    TEST_ASSERT_EQUAL_STRING(
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
        hexOf(s.data(), s.size()).c_str());
}

void test_sha256_incremental_matches_one_shot() {
    // Awkward chunk sizes across the 64-byte block boundary: this is where a
    // buffering bug hides, and the device hashes records piecemeal.
    const std::string msg =
        "the quick brown fox jumps over the lazy dog, repeatedly, for a while";
    uint8_t oneShot[kSha256DigestLen];
    sha256(msg.data(), msg.size(), oneShot);

    for (size_t chunk : {1u, 3u, 7u, 31u, 63u, 64u, 65u}) {
        Sha256 h;
        for (size_t i = 0; i < msg.size(); i += chunk) {
            const size_t n = std::min(chunk, msg.size() - i);
            h.update(msg.data() + i, n);
        }
        uint8_t inc[kSha256DigestLen];
        h.finish(inc);
        TEST_ASSERT_TRUE(equalConstantTime(oneShot, inc));
    }
}

void test_sha256_exact_block_boundaries() {
    // 55, 56 and 64 bytes straddle the padding edge cases.
    for (size_t n : {size_t(55), size_t(56), size_t(57), size_t(63), size_t(64),
                     size_t(65), size_t(119), size_t(120)}) {
        std::string s(n, 'x');
        uint8_t a[kSha256DigestLen], b[kSha256DigestLen];
        sha256(s.data(), s.size(), a);
        Sha256 h;
        h.update(s.data(), s.size());
        h.finish(b);
        TEST_ASSERT_TRUE(equalConstantTime(a, b));
    }
}

void test_constant_time_compare_detects_every_position() {
    uint8_t a[kSha256DigestLen];
    for (size_t i = 0; i < kSha256DigestLen; i++) a[i] = static_cast<uint8_t>(i);
    for (size_t i = 0; i < kSha256DigestLen; i++) {
        uint8_t b[kSha256DigestLen];
        std::memcpy(b, a, sizeof(b));
        b[i] ^= 0x01;
        TEST_ASSERT_FALSE(equalConstantTime(a, b));
    }
    TEST_ASSERT_TRUE(equalConstantTime(a, a));
}

// ---- the chain --------------------------------------------------------------

void test_clean_log_verifies() {
    const Log log = buildLog();
    const auto rep = verifyLog(log, log.head);
    TEST_ASSERT_TRUE(rep.ok());
    TEST_ASSERT_EQUAL_UINT32(6, rep.recordsOk);
}

void test_chain_is_deterministic() {
    const Log a = buildLog();
    const Log b = buildLog();
    TEST_ASSERT_TRUE(equalConstantTime(a.head, b.head));
}

void test_editing_a_finding_is_caught() {
    // The attack that matters: quietly downgrade a finding after the fact.
    Log log = buildLog();
    std::snprintf(log.records[4].detail, kDetailLen, "260ABCDE fcnt-reset 10");

    const auto rep = verifyLog(log, log.head);
    TEST_ASSERT_FALSE(rep.ok());
    TEST_ASSERT_EQUAL(static_cast<int>(VerifyStatus::DigestMismatch),
                      static_cast<int>(rep.status));
    TEST_ASSERT_EQUAL_UINT32(4, rep.failedAt);
    TEST_ASSERT_EQUAL_UINT32(4, rep.recordsOk);  // everything before it still good
}

void test_changing_a_timestamp_is_caught() {
    Log log = buildLog();
    log.records[2].timeMs += 1;
    TEST_ASSERT_FALSE(verifyLog(log, log.head).ok());
}

void test_deleting_a_record_is_caught() {
    Log log = buildLog();
    log.records.erase(log.records.begin() + 3);
    log.digests.erase(log.digests.begin() + 3);

    const auto rep = verifyLog(log, log.head);
    TEST_ASSERT_FALSE(rep.ok());
    TEST_ASSERT_EQUAL(static_cast<int>(VerifyStatus::SequenceBroken),
                      static_cast<int>(rep.status));
}

void test_reordering_records_is_caught() {
    Log log = buildLog();
    std::swap(log.records[1], log.records[3]);
    std::swap(log.digests[1], log.digests[3]);
    TEST_ASSERT_FALSE(verifyLog(log, log.head).ok());
}

void test_inserting_a_record_is_caught() {
    Log log = buildLog();
    log.records.insert(log.records.begin() + 2,
                       makeRecord(2, RecordKind::Note, "nothing to see here"));
    log.digests.insert(log.digests.begin() + 2, log.digests[2]);
    TEST_ASSERT_FALSE(verifyLog(log, log.head).ok());
}

void test_truncating_the_tail_is_caught_only_by_the_head() {
    // Dropping the last records leaves a chain that is internally perfect --
    // this is the honest limit of a keyless chain, and the reason the device
    // shows the head digest for the operator to record.
    Log log = buildLog();
    log.records.resize(4);
    log.digests.resize(4);

    const auto internal = verifyLog(log);  // no expected head
    TEST_ASSERT_TRUE(internal.ok());       // looks fine on its own

    const auto withHead = verifyLog(log, log.head);
    TEST_ASSERT_FALSE(withHead.ok());
    TEST_ASSERT_EQUAL(static_cast<int>(VerifyStatus::HeadMismatch),
                      static_cast<int>(withHead.status));
}

void test_wholesale_rewrite_is_caught_only_by_the_head() {
    // The documented limitation, stated as a test so it cannot be forgotten:
    // an attacker who rewrites every record AND recomputes every digest passes
    // the internal check. Only a head recorded away from the file catches it.
    Log forged;
    Chain chain;
    chain.begin(kSeed, sizeof(kSeed));
    const Record rs[] = {
        makeRecord(0, RecordKind::SessionStart, "EU868 survey, site A"),
        makeRecord(1, RecordKind::Device, "26011BDA rssi -78 frames 14"),
        makeRecord(2, RecordKind::Finding, "26011BDA all-clear 0"),
    };
    for (const auto& r : rs) {
        std::array<uint8_t, kSha256DigestLen> d{};
        chain.append(r, d.data());
        forged.records.push_back(r);
        forged.digests.push_back(d);
    }
    std::memcpy(forged.head, chain.head(), kSha256DigestLen);

    TEST_ASSERT_TRUE(verifyLog(forged).ok());  // internally consistent: it would

    const Log genuine = buildLog();
    const auto rep = verifyLog(forged, genuine.head);  // against the real head
    TEST_ASSERT_FALSE(rep.ok());
}

void test_wrong_seed_fails() {
    const Log log = buildLog();
    const char other[] = "different-session";
    const auto rep = verify(log.records.data(),
                            reinterpret_cast<const uint8_t(*)[kSha256DigestLen]>(
                                log.digests.data()),
                            log.records.size(), other, sizeof(other), nullptr);
    TEST_ASSERT_FALSE(rep.ok());
}

void test_empty_log_reported_as_empty() {
    const auto rep = verify(nullptr, nullptr, 0, kSeed, sizeof(kSeed), nullptr);
    TEST_ASSERT_EQUAL(static_cast<int>(VerifyStatus::Empty),
                      static_cast<int>(rep.status));
}

void test_detail_padding_is_hashed() {
    // Two records whose detail strings are equal up to the terminator but
    // differ after it must not hash the same.
    Record a = makeRecord(0, RecordKind::Note, "hello");
    Record b = a;
    b.detail[10] = 'X';  // past the NUL

    uint8_t sa[kSerialisedLen], sb[kSerialisedLen];
    serialise(a, sa);
    serialise(b, sb);
    TEST_ASSERT_NOT_EQUAL(0, std::memcmp(sa, sb, kSerialisedLen));
}

void test_names_present() {
    for (int i = 0; i <= static_cast<int>(VerifyStatus::HeadMismatch); i++)
        TEST_ASSERT_TRUE(std::strlen(verifyStatusName(static_cast<VerifyStatus>(i))) > 0);
    for (int i = 0; i <= static_cast<int>(RecordKind::SessionEnd); i++)
        TEST_ASSERT_TRUE(std::strlen(recordKindName(static_cast<RecordKind>(i))) > 0);
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_sha256_empty_string);
    RUN_TEST(test_sha256_abc);
    RUN_TEST(test_sha256_448_bit_message);
    RUN_TEST(test_sha256_896_bit_message);
    RUN_TEST(test_sha256_one_million_a);
    RUN_TEST(test_sha256_incremental_matches_one_shot);
    RUN_TEST(test_sha256_exact_block_boundaries);
    RUN_TEST(test_constant_time_compare_detects_every_position);

    RUN_TEST(test_clean_log_verifies);
    RUN_TEST(test_chain_is_deterministic);
    RUN_TEST(test_editing_a_finding_is_caught);
    RUN_TEST(test_changing_a_timestamp_is_caught);
    RUN_TEST(test_deleting_a_record_is_caught);
    RUN_TEST(test_reordering_records_is_caught);
    RUN_TEST(test_inserting_a_record_is_caught);
    RUN_TEST(test_truncating_the_tail_is_caught_only_by_the_head);
    RUN_TEST(test_wholesale_rewrite_is_caught_only_by_the_head);
    RUN_TEST(test_wrong_seed_fails);
    RUN_TEST(test_empty_log_reported_as_empty);
    RUN_TEST(test_detail_padding_is_hashed);
    RUN_TEST(test_names_present);

    return UNITY_END();
}
