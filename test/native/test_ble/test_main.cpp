// Host tests for BLE advertisement parsing and classification.

#include <unity.h>

#include <cstdio>
#include <cstring>

#include "ble/advert.h"

using namespace orthrus::ble;

namespace {

// Builds an advertisement out of AD structures, the way a real one is laid out:
// length, type, payload -- where the length counts the type byte too.
struct Builder {
    uint8_t buf[64] = {0};
    size_t  len     = 0;

    Builder& ad(uint8_t type, const uint8_t* payload, size_t plen) {
        buf[len++] = static_cast<uint8_t>(plen + 1);
        buf[len++] = type;
        std::memcpy(buf + len, payload, plen);
        len += plen;
        return *this;
    }

    Builder& name(const char* s) {
        return ad(0x09, reinterpret_cast<const uint8_t*>(s), std::strlen(s));
    }

    Builder& service16(uint16_t uuid) {
        const uint8_t p[2] = {static_cast<uint8_t>(uuid & 0xFF),
                              static_cast<uint8_t>(uuid >> 8)};
        return ad(0x03, p, 2);
    }

    Builder& apple(uint8_t type, uint8_t appleLen, size_t extra = 4) {
        uint8_t p[24] = {0x4C, 0x00, type, appleLen};
        return ad(0xFF, p, 4 + extra);
    }
};

Advert parse(const Builder& b) {
    Advert a;
    TEST_ASSERT_TRUE(parseAdvert(b.buf, b.len, a));
    return a;
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- parsing -----------------------------------------------------------------

void test_name_service_and_power_are_all_read() {
    Builder b;
    const uint8_t flags[1] = {0x06};
    const uint8_t power[1] = {static_cast<uint8_t>(-59)};
    b.ad(0x01, flags, 1).name("front door").service16(0x180F).ad(0x0A, power, 1);

    const Advert a = parse(b);
    TEST_ASSERT_TRUE(a.hasName);
    TEST_ASSERT_EQUAL_STRING("front door", a.name);
    TEST_ASSERT_FALSE(a.nameShortened);
    TEST_ASSERT_TRUE(a.hasService(0x180F));
    TEST_ASSERT_TRUE(a.hasTxPower);
    TEST_ASSERT_EQUAL_INT8(-59, a.txPower);
    TEST_ASSERT_TRUE(a.hasFlags);
    TEST_ASSERT_FALSE(a.truncated);
}

void test_a_structure_running_past_the_end_keeps_what_came_before_it() {
    // Discarding a valid name because the LAST field was malformed would hand
    // anyone a one-byte way to drop off the list entirely.
    Builder b;
    b.name("real name");
    b.buf[b.len++] = 40;    // claims forty bytes
    b.buf[b.len++] = 0xFF;
    b.len += 2;

    const Advert a = parse(b);
    TEST_ASSERT_TRUE(a.truncated);
    TEST_ASSERT_TRUE(a.hasName);
    TEST_ASSERT_EQUAL_STRING("real name", a.name);
}

void test_control_bytes_in_a_name_are_replaced() {
    // A name is arbitrary bytes somebody typed. A newline in one would split a
    // record in the evidence log.
    Builder b;
    b.name("bad\nname\x01");

    const Advert a = parse(b);
    TEST_ASSERT_NULL(std::strchr(a.name, '\n'));
    TEST_ASSERT_EQUAL_STRING("bad name ", a.name);
}

void test_an_overlong_name_is_clamped() {
    Builder b;
    b.name("012345678901234567890123456789");

    const Advert a = parse(b);
    TEST_ASSERT_EQUAL_size_t(kNameMax, std::strlen(a.name));
}

void test_zero_length_padding_ends_the_walk() {
    Builder b;
    b.name("x");
    b.buf[b.len++] = 0;   // padding
    b.len += 6;

    const Advert a = parse(b);
    TEST_ASSERT_FALSE(a.truncated);
    TEST_ASSERT_EQUAL_STRING("x", a.name);
}

void test_service_data_contributes_its_uuid() {
    // Several trackers only ever name themselves in the service DATA, never in
    // a service list, and looking in one place misses them.
    Builder b;
    const uint8_t sd[4] = {0xED, 0xFE, 0x01, 0x02};
    b.ad(0x16, sd, 4);

    const Advert a = parse(b);
    TEST_ASSERT_TRUE(a.hasService(kServiceTile));
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::TileTracker),
                      static_cast<int>(classify(a)));
}

void test_an_empty_advert_parses_to_nothing_rather_than_failing() {
    Advert a;
    const uint8_t empty[1] = {0};
    TEST_ASSERT_TRUE(parseAdvert(empty, 0, a));
    TEST_ASSERT_FALSE(a.hasName);
    TEST_ASSERT_FALSE(parseAdvert(nullptr, 10, a));
}

// ---- classification -----------------------------------------------------------

void test_find_my_is_recognised_from_apples_subtype() {
    Builder b;
    b.apple(kAppleFindMy, 0x19, 20);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::FindMy),
                      static_cast<int>(classify(parse(b))));
}

void test_apple_earbuds_are_not_reported_as_a_tracker() {
    // Both are company 0x004C. Calling every Apple advert a tracker teaches the
    // operator to ignore the label, which is worse than not having one.
    Builder b;
    b.apple(kAppleProximityPair, 0x19, 20);
    const Kind k = classify(parse(b));
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::Continuity), static_cast<int>(k));
    TEST_ASSERT_FALSE(isTracker(k));
}

void test_ibeacon_needs_the_right_length_as_well_as_the_right_type() {
    Builder good;
    good.apple(kAppleIBeacon, 0x15, 21);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::IBeacon),
                      static_cast<int>(classify(parse(good))));

    Builder wrong;
    wrong.apple(kAppleIBeacon, 0x08, 21);
    TEST_ASSERT_NOT_EQUAL(static_cast<int>(Kind::IBeacon),
                          static_cast<int>(classify(parse(wrong))));
}

void test_the_tracker_set_is_deliberately_narrow() {
    TEST_ASSERT_TRUE(isTracker(Kind::FindMy));
    TEST_ASSERT_TRUE(isTracker(Kind::TileTracker));
    TEST_ASSERT_TRUE(isTracker(Kind::SamsungTag));
    // A beacon in a shop window is not following anybody.
    TEST_ASSERT_FALSE(isTracker(Kind::IBeacon));
    TEST_ASSERT_FALSE(isTracker(Kind::Eddystone));
    TEST_ASSERT_FALSE(isTracker(Kind::FastPair));
    TEST_ASSERT_FALSE(isTracker(Kind::Generic));
}

void test_a_name_alone_never_decides_the_kind() {
    // Half the trackers in the world are called "iPhone".
    Builder b;
    b.name("AirTag");
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::Generic),
                      static_cast<int>(classify(parse(b))));
}

void test_unknown_company_identifiers_are_left_as_numbers() {
    TEST_ASSERT_EQUAL_STRING("Apple", companyName(kCompanyApple));
    TEST_ASSERT_EQUAL_STRING("Tile", companyName(kCompanyTile));
    TEST_ASSERT_NULL(companyName(0xABCD));
}

// ---- addresses ----------------------------------------------------------------

void test_address_kind_comes_from_the_top_two_bits() {
    const uint8_t staticRandom[6] = {0xC3, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t resolvable[6]   = {0x41, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t nonResolvable[6] = {0x21, 0x11, 0x22, 0x33, 0x44, 0x55};

    TEST_ASSERT_EQUAL(static_cast<int>(AddressKind::RandomStatic),
                      static_cast<int>(addressKind(staticRandom, true)));
    TEST_ASSERT_EQUAL(static_cast<int>(AddressKind::ResolvablePrivate),
                      static_cast<int>(addressKind(resolvable, true)));
    TEST_ASSERT_EQUAL(static_cast<int>(AddressKind::NonResolvablePrivate),
                      static_cast<int>(addressKind(nonResolvable, true)));

    // The same bytes with the random flag clear are a public address, whatever
    // the top bits happen to be.
    TEST_ASSERT_EQUAL(static_cast<int>(AddressKind::Public),
                      static_cast<int>(addressKind(staticRandom, false)));
}

void test_only_public_and_static_addresses_can_be_followed() {
    TEST_ASSERT_TRUE(addressIsStable(AddressKind::Public));
    TEST_ASSERT_TRUE(addressIsStable(AddressKind::RandomStatic));
    TEST_ASSERT_FALSE(addressIsStable(AddressKind::ResolvablePrivate));
    TEST_ASSERT_FALSE(addressIsStable(AddressKind::NonResolvablePrivate));
}

// ---- range --------------------------------------------------------------------

void test_proximity_bands_widen_as_the_signal_falls() {
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Immediate),
                      static_cast<int>(proximityFor(-55, true, -59)));
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Near),
                      static_cast<int>(proximityFor(-70, true, -59)));
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Far),
                      static_cast<int>(proximityFor(-85, true, -59)));
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Distant),
                      static_cast<int>(proximityFor(-99, true, -59)));
}

void test_a_missing_rssi_is_unknown_not_touching_the_antenna() {
    // Scanners report 0 when they have no reading. Treating that as the
    // strongest possible signal puts a phantom device in the operator's hand.
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Unknown),
                      static_cast<int>(proximityFor(0, false, 0)));
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Unknown),
                      static_cast<int>(proximityFor(-200, false, 0)));
}

void test_proximity_falls_back_to_raw_rssi_without_a_calibrated_power() {
    TEST_ASSERT_EQUAL(static_cast<int>(Proximity::Near),
                      static_cast<int>(proximityFor(-70, false, 0)));
}

// -------------------------------------------------------------------------------

int main() {
    UNITY_BEGIN();

    RUN_TEST(test_name_service_and_power_are_all_read);
    RUN_TEST(test_a_structure_running_past_the_end_keeps_what_came_before_it);
    RUN_TEST(test_control_bytes_in_a_name_are_replaced);
    RUN_TEST(test_an_overlong_name_is_clamped);
    RUN_TEST(test_zero_length_padding_ends_the_walk);
    RUN_TEST(test_service_data_contributes_its_uuid);
    RUN_TEST(test_an_empty_advert_parses_to_nothing_rather_than_failing);

    RUN_TEST(test_find_my_is_recognised_from_apples_subtype);
    RUN_TEST(test_apple_earbuds_are_not_reported_as_a_tracker);
    RUN_TEST(test_ibeacon_needs_the_right_length_as_well_as_the_right_type);
    RUN_TEST(test_the_tracker_set_is_deliberately_narrow);
    RUN_TEST(test_a_name_alone_never_decides_the_kind);
    RUN_TEST(test_unknown_company_identifiers_are_left_as_numbers);

    RUN_TEST(test_address_kind_comes_from_the_top_two_bits);
    RUN_TEST(test_only_public_and_static_addresses_can_be_followed);

    RUN_TEST(test_proximity_bands_widen_as_the_signal_falls);
    RUN_TEST(test_a_missing_rssi_is_unknown_not_touching_the_antenna);
    RUN_TEST(test_proximity_falls_back_to_raw_rssi_without_a_calibrated_power);

    return UNITY_END();
}
