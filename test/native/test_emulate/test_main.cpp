// Host tests for the Bluetooth advertisements this device builds to BE a
// named product.
//
// THE ROUND TRIP IS THE POINT
//
// Every builder here is parsed back through this firmware's OWN classifier and
// asserted to come out as the product it set out to be. That closes the loop
// the whole feature rests on: an emulation that its own detector cannot name is
// either a broken builder or a broken classifier, and either way the operator
// would be told a tracker was being emitted when nothing recognisable was on
// the air.
//
// It is also the reason the vendors' real identifiers are used. A classifier
// keying on Apple's 0x004C will CORRECTLY ignore an advertisement built from
// the SIG's reserved test identifier, so these tests would pass with the test
// id and prove nothing at all.

#include <unity.h>

#include <cstring>

#include "ble/emulate.h"

using namespace orthrus::ble;

namespace {

Advert parse(const uint8_t* data, size_t len) {
    Advert a;
    parseAdvert(data, len, a);
    return a;
}

Kind kindOf(const uint8_t* data, size_t len) {
    const Advert a = parse(data, len);
    return classify(a);
}

// Walks the AD structures and asserts every length byte adds up exactly to the
// end of the payload. A structure whose length is one too long or one too short
// is the single most common defect in this format, and it does not throw -- the
// receiver simply stops parsing, so a name or a service UUID silently vanishes.
bool adStructuresAreWellFormed(const uint8_t* data, size_t len) {
    size_t i = 0;
    while (i < len) {
        const uint8_t adLen = data[i];
        if (adLen == 0) return false;            // no padding is emitted here
        if (i + 1 + adLen > len) return false;   // claims more than it has
        i += 1 + adLen;
    }
    return i == len;                             // and lands exactly on the end
}

const uint8_t kKey[kFindMyKeyLen] = {
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18, 0x29, 0x3A, 0x4B,
    0x5C, 0x6D, 0x7E, 0x8F, 0x90, 0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6};
const uint8_t kId[6]    = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
const uint8_t kModel[3] = {0x0A, 0x1B, 0x2C};

}  // namespace

void setUp() {}
void tearDown() {}

// ---- well-formedness, for every builder ------------------------------------

void test_every_builder_produces_well_formed_ad_structures() {
    uint8_t b[kAdvertMax];
    size_t n;

    n = buildFindMy(b, sizeof(b), kKey, 0x10);
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));

    n = buildTile(b, sizeof(b), kId);
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));

    n = buildSmartTag(b, sizeof(b), kId);
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));

    n = buildFastPair(b, sizeof(b), kModel);
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));

    n = buildSwiftPair(b, sizeof(b), "ORTHRUS-TEST");
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));

    n = buildFlipper(b, sizeof(b), "Flipper Orthrus", 1);
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));
}

void test_no_builder_exceeds_the_thirty_one_byte_payload() {
    uint8_t b[kAdvertMax];
    for (uint8_t i = 0; i < static_cast<uint8_t>(Emulation::Count); i++) {
        const size_t n = buildEmulation(static_cast<Emulation>(i), b, sizeof(b), i);
        TEST_ASSERT_TRUE(n > 0);
        TEST_ASSERT_TRUE(n <= kAdvertMax);
    }
}

void test_a_buffer_too_small_writes_nothing_rather_than_a_partial_advert() {
    uint8_t tiny[4];
    TEST_ASSERT_EQUAL_size_t(0, buildFindMy(tiny, sizeof(tiny), kKey, 0));
    TEST_ASSERT_EQUAL_size_t(0, buildTile(tiny, sizeof(tiny), kId));
    TEST_ASSERT_EQUAL_size_t(0, buildSmartTag(tiny, sizeof(tiny), kId));
    TEST_ASSERT_EQUAL_size_t(0, buildFastPair(tiny, sizeof(tiny), kModel));
    TEST_ASSERT_EQUAL_size_t(0, buildSwiftPair(tiny, sizeof(tiny), "x"));
    TEST_ASSERT_EQUAL_size_t(0, buildFlipper(tiny, sizeof(tiny), "x", 0));
}

void test_a_null_argument_is_refused() {
    uint8_t b[kAdvertMax];
    TEST_ASSERT_EQUAL_size_t(0, buildFindMy(nullptr, sizeof(b), kKey, 0));
    TEST_ASSERT_EQUAL_size_t(0, buildFindMy(b, sizeof(b), nullptr, 0));
    TEST_ASSERT_EQUAL_size_t(0, buildTile(b, sizeof(b), nullptr));
    TEST_ASSERT_EQUAL_size_t(0, buildFastPair(b, sizeof(b), nullptr));
}

// ---- Find My ----------------------------------------------------------------

void test_find_my_fills_the_payload_exactly_with_no_flags_structure() {
    // A real tracker advertisement is one 31-byte manufacturer structure and
    // nothing else -- there is no room for a flags structure, and a
    // non-connectable undirected advertiser does not need one.
    uint8_t b[kAdvertMax];
    const size_t n = buildFindMy(b, sizeof(b), kKey, 0x10);
    TEST_ASSERT_EQUAL_size_t(31, n);
    TEST_ASSERT_EQUAL_UINT8(0x1E, b[0]);   // 30 bytes follow this one
    TEST_ASSERT_EQUAL_UINT8(0xFF, b[1]);   // manufacturer specific data
    TEST_ASSERT_EQUAL_UINT8(0x4C, b[2]);   // Apple, little endian
    TEST_ASSERT_EQUAL_UINT8(0x00, b[3]);
    TEST_ASSERT_EQUAL_UINT8(0x12, b[4]);   // Find My subtype
    TEST_ASSERT_EQUAL_UINT8(0x19, b[5]);   // 25 bytes of it
    TEST_ASSERT_EQUAL_UINT8(0x10, b[6]);   // status
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kKey, b + 7, kFindMyKeyLen);
}

void test_find_my_is_classified_as_find_my_by_this_firmwares_own_detector() {
    uint8_t b[kAdvertMax];
    const size_t n = buildFindMy(b, sizeof(b), kKey, 0x10);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::FindMy),
                      static_cast<int>(kindOf(b, n)));
    TEST_ASSERT_TRUE(isTracker(kindOf(b, n)));
}

void test_find_my_parses_back_with_apples_company_and_subtype() {
    uint8_t b[kAdvertMax];
    const size_t n = buildFindMy(b, sizeof(b), kKey, 0x10);
    const Advert a = parse(b, n);
    TEST_ASSERT_TRUE(a.hasCompany);
    TEST_ASSERT_EQUAL_UINT16(kCompanyApple, a.companyId);
    TEST_ASSERT_EQUAL_UINT8(kAppleFindMy, a.appleType);
    TEST_ASSERT_EQUAL_UINT8(0x19, a.appleLen);
    TEST_ASSERT_FALSE(a.truncated);
}

void test_find_my_is_not_mistaken_for_an_ibeacon() {
    // iBeacon is checked by its length as well as its type. A Find My payload
    // has a different subtype and a different length, and must not fall into
    // the iBeacon branch.
    uint8_t b[kAdvertMax];
    const size_t n = buildFindMy(b, sizeof(b), kKey, 0x10);
    TEST_ASSERT_NOT_EQUAL(static_cast<int>(Kind::IBeacon),
                          static_cast<int>(kindOf(b, n)));
}

// ---- Tile -------------------------------------------------------------------

void test_tile_is_classified_as_a_tile() {
    uint8_t b[kAdvertMax];
    const size_t n = buildTile(b, sizeof(b), kId);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::TileTracker),
                      static_cast<int>(kindOf(b, n)));
    TEST_ASSERT_TRUE(isTracker(kindOf(b, n)));
}

void test_tile_can_emit_either_of_the_two_uuids_it_has_shipped() {
    // A detector that knows only the older UUID files a modern Tile as a
    // generic device, which is a false negative in the one place false
    // negatives matter. Being able to emit both is how that gets demonstrated.
    uint8_t b[kAdvertMax];

    size_t n = buildTile(b, sizeof(b), kId, kServiceTile);
    TEST_ASSERT_TRUE(parse(b, n).hasService(kServiceTile));
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::TileTracker),
                      static_cast<int>(kindOf(b, n)));

    n = buildTile(b, sizeof(b), kId, kServiceTileNew);
    TEST_ASSERT_TRUE(parse(b, n).hasService(kServiceTileNew));
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::TileTracker),
                      static_cast<int>(kindOf(b, n)));
}

void test_tile_puts_its_uuid_in_the_service_list_and_in_the_service_data() {
    // Several trackers put it ONLY in service data, and a classifier reading
    // just the service list misses them -- so an emulation that omitted it
    // would be testing a path real devices do not always use.
    uint8_t b[kAdvertMax];
    const size_t n = buildTile(b, sizeof(b), kId);

    bool sawList = false, sawData = false;
    size_t i = 0;
    while (i < n) {
        const uint8_t adLen = b[i], type = b[i + 1];
        if (type == 0x03) sawList = true;
        if (type == 0x16) {
            sawData = true;
            TEST_ASSERT_EQUAL_UINT8(0xED, b[i + 2]);
            TEST_ASSERT_EQUAL_UINT8(0xFE, b[i + 3]);
            TEST_ASSERT_EQUAL_UINT8_ARRAY(kId, b + i + 4, 6);
        }
        i += 1 + adLen;
    }
    TEST_ASSERT_TRUE(sawList);
    TEST_ASSERT_TRUE(sawData);
}

// ---- SmartTag ---------------------------------------------------------------

void test_smarttag_is_classified_by_its_service_uuid() {
    uint8_t b[kAdvertMax];
    const size_t n = buildSmartTag(b, sizeof(b), kId);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::SamsungTag),
                      static_cast<int>(kindOf(b, n)));
    TEST_ASSERT_TRUE(parse(b, n).hasService(kServiceSamsung));
}

void test_smarttag_does_not_rely_on_samsungs_company_identifier() {
    // Every Galaxy phone, watch and pair of earbuds carries 0x0075, and
    // classify() deliberately does NOT treat it as a tag. An emulation built
    // from the company id would therefore exercise a path that should not fire
    // -- and would pass only if the classifier had the bug.
    uint8_t b[kAdvertMax];
    const size_t n = buildSmartTag(b, sizeof(b), kId);
    const Advert a = parse(b, n);
    TEST_ASSERT_FALSE(a.hasCompany);
}

// ---- Fast Pair --------------------------------------------------------------

void test_fast_pair_is_classified_as_fast_pair() {
    uint8_t b[kAdvertMax];
    const size_t n = buildFastPair(b, sizeof(b), kModel);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::FastPair),
                      static_cast<int>(kindOf(b, n)));
    // It solicits pairing. It is not an item finder, and calling it one would
    // teach an operator to ignore the word.
    TEST_ASSERT_FALSE(isTracker(kindOf(b, n)));
}

void test_fast_pair_carries_the_three_byte_model_identifier_the_phone_looks_up() {
    uint8_t b[kAdvertMax];
    const size_t n = buildFastPair(b, sizeof(b), kModel);
    size_t i = 0;
    bool sawModel = false;
    while (i < n) {
        const uint8_t adLen = b[i], type = b[i + 1];
        if (type == 0x16) {
            TEST_ASSERT_EQUAL_UINT8(0x2C, b[i + 2]);
            TEST_ASSERT_EQUAL_UINT8(0xFE, b[i + 3]);
            TEST_ASSERT_EQUAL_UINT8_ARRAY(kModel, b + i + 4, 3);
            // Length exactly 5: UUID and model and nothing else. The
            // discoverable form is what raises the dialog.
            TEST_ASSERT_EQUAL_UINT8(6, adLen);
            sawModel = true;
        }
        i += 1 + adLen;
    }
    TEST_ASSERT_TRUE(sawModel);
}

// ---- Swift Pair -------------------------------------------------------------

void test_swift_pair_is_classified_as_swift_pair() {
    uint8_t b[kAdvertMax];
    const size_t n = buildSwiftPair(b, sizeof(b), "ORTHRUS-TEST");
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::SwiftPair),
                      static_cast<int>(kindOf(b, n)));
    TEST_ASSERT_FALSE(isTracker(kindOf(b, n)));
}

void test_swift_pair_carries_microsofts_company_and_beacon_identifier() {
    uint8_t b[kAdvertMax];
    const size_t n = buildSwiftPair(b, sizeof(b), "ORTHRUS-TEST");
    const Advert a = parse(b, n);
    TEST_ASSERT_TRUE(a.hasCompany);
    TEST_ASSERT_EQUAL_UINT16(kCompanyMicrosoft, a.companyId);
    TEST_ASSERT_TRUE(a.hasMfgPayload);
    TEST_ASSERT_EQUAL_UINT8(kMicrosoftBeaconSwiftPair, a.mfgFirst);
}

void test_a_windows_machine_advertising_something_else_is_not_swift_pair() {
    // The classification is company AND the published beacon byte. A laptop
    // advertising anything else under 0x0006 must not be filed as a pairing
    // solicitation.
    uint8_t b[8];
    b[0] = 0x05; b[1] = 0xFF;
    b[2] = 0x06; b[3] = 0x00;    // Microsoft
    b[4] = 0x01;                 // some other beacon id
    b[5] = 0x00; b[6] = 0x00;
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::Generic),
                      static_cast<int>(kindOf(b, 6)));
}

void test_the_swift_pair_display_name_is_the_one_label_worth_keeping() {
    // It is shown to the person. Somebody who is interrupted should be able to
    // read what interrupted them.
    uint8_t b[kAdvertMax];
    const size_t n = buildSwiftPair(b, sizeof(b), "ORTHRUS-TEST");
    bool found = false;
    for (size_t i = 0; i + 12 <= n; i++) {
        if (std::memcmp(b + i, "ORTHRUS-TEST", 12) == 0) found = true;
    }
    TEST_ASSERT_TRUE(found);
}

void test_an_overlong_swift_pair_name_is_truncated_not_overflowed() {
    uint8_t b[kAdvertMax];
    const size_t n = buildSwiftPair(
        b, sizeof(b), "ORTHRUS-THIS-NAME-IS-FAR-TOO-LONG-FOR-ONE-ADVERT");
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_TRUE(n <= kAdvertMax);
    TEST_ASSERT_TRUE(adStructuresAreWellFormed(b, n));
}

// ---- Flipper ----------------------------------------------------------------

void test_the_flipper_emulation_carries_a_name_and_no_invented_company_id() {
    // A company identifier was written here first, from memory rather than
    // from the registry -- the same mistake that put a real brand's name
    // against an Espressif OUI in somebody else's firmware. An identifier that
    // cannot be checked does not go on the air.
    uint8_t b[kAdvertMax];
    const size_t n = buildFlipper(b, sizeof(b), "Flipper Orthrus", 1);
    const Advert a = parse(b, n);
    TEST_ASSERT_TRUE(a.hasName);
    TEST_ASSERT_EQUAL_STRING("Flipper Orthrus", a.name);
    TEST_ASSERT_FALSE(a.hasCompany);
    TEST_ASSERT_TRUE(a.hasTxPower);
}

void test_the_flipper_emulation_is_honestly_a_generic_device_to_this_detector() {
    // This firmware's classifier does not act on names -- half the trackers in
    // the world are called "iPhone" -- so it files this as a generic device
    // carrying that name, and that is the right answer. The emulation exists to
    // test detectors that DO key on the name, and the screen says so.
    uint8_t b[kAdvertMax];
    const size_t n = buildFlipper(b, sizeof(b), "Flipper Orthrus", 1);
    TEST_ASSERT_EQUAL(static_cast<int>(Kind::Generic),
                      static_cast<int>(kindOf(b, n)));
}

void test_an_empty_flipper_name_falls_back_rather_than_advertising_nothing() {
    uint8_t b[kAdvertMax];
    size_t n = buildFlipper(b, sizeof(b), nullptr, 0);
    TEST_ASSERT_TRUE(parse(b, n).hasName);
    n = buildFlipper(b, sizeof(b), "", 0);
    TEST_ASSERT_TRUE(parse(b, n).hasName);
}

// ---- identities -------------------------------------------------------------

void test_a_random_static_address_has_both_top_bits_set() {
    // Static rather than resolvable-private: a swarm whose members rotate
    // underneath it cannot be counted by the thing being tested.
    for (uint32_t salt = 0; salt < 300; salt++) {
        uint8_t a[kAddrLen];
        randomStaticAddress(a, salt);
        TEST_ASSERT_EQUAL_UINT8(0xC0, a[0] & 0xC0);
        TEST_ASSERT_EQUAL(static_cast<int>(AddressKind::RandomStatic),
                          static_cast<int>(addressKind(a, true)));
        TEST_ASSERT_TRUE(addressIsStable(addressKind(a, true)));
    }
}

void test_identities_are_reproducible_and_distinct() {
    uint8_t a[16], b[16], again[16];
    deriveIdentity(a, sizeof(a), 1);
    deriveIdentity(b, sizeof(b), 2);
    deriveIdentity(again, sizeof(again), 1);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(a, again, sizeof(a));
    TEST_ASSERT_TRUE(std::memcmp(a, b, sizeof(a)) != 0);
}

void test_a_derived_identity_is_not_all_one_byte() {
    // A key of 22 identical bytes would still classify correctly and would be
    // obviously synthetic to anything looking at it.
    uint8_t k[kFindMyKeyLen];
    deriveIdentity(k, sizeof(k), 7);
    bool varied = false;
    for (size_t i = 1; i < sizeof(k); i++)
        if (k[i] != k[0]) { varied = true; break; }
    TEST_ASSERT_TRUE(varied);
}

void test_two_swarm_members_differ_in_their_payloads() {
    uint8_t a[kAdvertMax], b[kAdvertMax];
    const size_t na = buildEmulation(Emulation::FindMy, a, sizeof(a), 1);
    const size_t nb = buildEmulation(Emulation::FindMy, b, sizeof(b), 2);
    TEST_ASSERT_EQUAL_size_t(na, nb);
    TEST_ASSERT_TRUE(std::memcmp(a, b, na) != 0);
}

// ---- the set ----------------------------------------------------------------

void test_only_the_two_pairing_emulations_pop_a_dialog() {
    TEST_ASSERT_TRUE(emulationPopsDialog(Emulation::FastPair));
    TEST_ASSERT_TRUE(emulationPopsDialog(Emulation::SwiftPair));
    TEST_ASSERT_FALSE(emulationPopsDialog(Emulation::FindMy));
    TEST_ASSERT_FALSE(emulationPopsDialog(Emulation::Tile));
    TEST_ASSERT_FALSE(emulationPopsDialog(Emulation::SmartTag));
    TEST_ASSERT_FALSE(emulationPopsDialog(Emulation::Flipper));
}

void test_a_swarm_can_never_reach_a_family_that_raises_a_dialog() {
    // A volume test that interrupts forty strangers is not a test. The
    // rotation table is the guard, so a caller cannot ask for it by mistake.
    for (uint32_t n = 0; n < 1000; n++) {
        const Emulation e = swarmStep(n);
        TEST_ASSERT_FALSE(emulationPopsDialog(e));
    }
}

void test_a_swarm_rotates_through_all_four_observational_families() {
    bool seen[static_cast<size_t>(Emulation::Count)] = {false};
    for (uint32_t n = 0; n < 40; n++)
        seen[static_cast<size_t>(swarmStep(n))] = true;
    TEST_ASSERT_TRUE(seen[static_cast<size_t>(Emulation::FindMy)]);
    TEST_ASSERT_TRUE(seen[static_cast<size_t>(Emulation::Tile)]);
    TEST_ASSERT_TRUE(seen[static_cast<size_t>(Emulation::SmartTag)]);
    TEST_ASSERT_TRUE(seen[static_cast<size_t>(Emulation::Flipper)]);
    TEST_ASSERT_FALSE(seen[static_cast<size_t>(Emulation::FastPair)]);
    TEST_ASSERT_FALSE(seen[static_cast<size_t>(Emulation::SwiftPair)]);
}

void test_every_emulation_has_a_name_and_builds_something() {
    for (uint8_t i = 0; i < static_cast<uint8_t>(Emulation::Count); i++) {
        const Emulation e = static_cast<Emulation>(i);
        TEST_ASSERT_TRUE(std::strlen(emulationName(e)) > 0);
        uint8_t b[kAdvertMax];
        TEST_ASSERT_TRUE(buildEmulation(e, b, sizeof(b), 1) > 0);
    }
    TEST_ASSERT_EQUAL_STRING("?", emulationName(Emulation::Count));
    uint8_t b[kAdvertMax];
    TEST_ASSERT_EQUAL_size_t(0, buildEmulation(Emulation::Count, b, sizeof(b), 1));
}

void test_each_emulation_classifies_as_what_it_set_out_to_be() {
    // The whole loop, in one assertion per family: the builder, this
    // firmware's parser, and this firmware's classifier all agree.
    struct Expect { Emulation e; Kind k; };
    const Expect table[] = {
        {Emulation::FindMy,    Kind::FindMy},
        {Emulation::Tile,      Kind::TileTracker},
        {Emulation::SmartTag,  Kind::SamsungTag},
        {Emulation::FastPair,  Kind::FastPair},
        {Emulation::SwiftPair, Kind::SwiftPair},
        // Honestly generic: the tell is a name, and this classifier does not
        // act on names.
        {Emulation::Flipper,   Kind::Generic},
    };
    for (const Expect& x : table) {
        uint8_t b[kAdvertMax];
        const size_t n = buildEmulation(x.e, b, sizeof(b), 5);
        TEST_ASSERT_TRUE(n > 0);
        TEST_ASSERT_EQUAL(static_cast<int>(x.k), static_cast<int>(kindOf(b, n)));
    }
}

int main() {
    UNITY_BEGIN();

    RUN_TEST(test_every_builder_produces_well_formed_ad_structures);
    RUN_TEST(test_no_builder_exceeds_the_thirty_one_byte_payload);
    RUN_TEST(test_a_buffer_too_small_writes_nothing_rather_than_a_partial_advert);
    RUN_TEST(test_a_null_argument_is_refused);

    RUN_TEST(test_find_my_fills_the_payload_exactly_with_no_flags_structure);
    RUN_TEST(test_find_my_is_classified_as_find_my_by_this_firmwares_own_detector);
    RUN_TEST(test_find_my_parses_back_with_apples_company_and_subtype);
    RUN_TEST(test_find_my_is_not_mistaken_for_an_ibeacon);

    RUN_TEST(test_tile_is_classified_as_a_tile);
    RUN_TEST(test_tile_can_emit_either_of_the_two_uuids_it_has_shipped);
    RUN_TEST(test_tile_puts_its_uuid_in_the_service_list_and_in_the_service_data);

    RUN_TEST(test_smarttag_is_classified_by_its_service_uuid);
    RUN_TEST(test_smarttag_does_not_rely_on_samsungs_company_identifier);

    RUN_TEST(test_fast_pair_is_classified_as_fast_pair);
    RUN_TEST(test_fast_pair_carries_the_three_byte_model_identifier_the_phone_looks_up);

    RUN_TEST(test_swift_pair_is_classified_as_swift_pair);
    RUN_TEST(test_swift_pair_carries_microsofts_company_and_beacon_identifier);
    RUN_TEST(test_a_windows_machine_advertising_something_else_is_not_swift_pair);
    RUN_TEST(test_the_swift_pair_display_name_is_the_one_label_worth_keeping);
    RUN_TEST(test_an_overlong_swift_pair_name_is_truncated_not_overflowed);

    RUN_TEST(test_the_flipper_emulation_carries_a_name_and_no_invented_company_id);
    RUN_TEST(test_the_flipper_emulation_is_honestly_a_generic_device_to_this_detector);
    RUN_TEST(test_an_empty_flipper_name_falls_back_rather_than_advertising_nothing);

    RUN_TEST(test_a_random_static_address_has_both_top_bits_set);
    RUN_TEST(test_identities_are_reproducible_and_distinct);
    RUN_TEST(test_a_derived_identity_is_not_all_one_byte);
    RUN_TEST(test_two_swarm_members_differ_in_their_payloads);

    RUN_TEST(test_only_the_two_pairing_emulations_pop_a_dialog);
    RUN_TEST(test_a_swarm_can_never_reach_a_family_that_raises_a_dialog);
    RUN_TEST(test_a_swarm_rotates_through_all_four_observational_families);
    RUN_TEST(test_every_emulation_has_a_name_and_builds_something);
    RUN_TEST(test_each_emulation_classifies_as_what_it_set_out_to_be);

    return UNITY_END();
}
