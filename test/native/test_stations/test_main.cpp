// Host tests for the station table: the devices in a room, and what their
// probe requests give away.

#include <unity.h>

#include <cstdio>
#include <cstring>

#include "dot11/stations.h"

using namespace orthrus::dot11;

namespace {

// 0xA8 = 1010 1000: bit 1 clear, so this is a real burned-in address. 0xAA
// would NOT be -- its bit 1 is set -- which is an easy way to write a test
// fixture that quietly disagrees with the thing it is testing.
const uint8_t kPhone[6]  = {0xA8, 0xBB, 0xCC, 0x11, 0x22, 0x33};  // universal
const uint8_t kRandom[6] = {0xA6, 0xBB, 0xCC, 0x11, 0x22, 0x44};  // bit 1 set
const uint8_t kAp[6]     = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t kBcast[6]  = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

StationTable& table() {
    static StationTable t;
    return t;
}

}  // namespace

void setUp() {}
void tearDown() {}

void test_a_device_is_recorded_once_however_often_it_speaks() {
    StationTable& t = table();
    t.clear();
    for (int i = 0; i < 20; i++) t.touch(kPhone, -50, 100 + i);

    TEST_ASSERT_EQUAL_UINT8(1, t.count());
    TEST_ASSERT_EQUAL_UINT32(20, t.at(0).frames);
}

void test_randomised_addresses_are_flagged() {
    // Bit 1 of the first octet is the locally-administered bit. Every phone
    // doing MAC randomisation sets it, and a list of thirty such addresses is
    // not thirty people.
    StationTable& t = table();
    t.clear();
    t.touch(kPhone, -50, 1);
    t.touch(kRandom, -50, 1);

    TEST_ASSERT_FALSE(t.at(0).randomised);
    TEST_ASSERT_TRUE(t.at(1).randomised);
}

void test_group_addresses_are_rejected_before_being_classified() {
    // Broadcast happens to have the locally-administered bit set, so asking
    // "is this randomised?" about it answers yes -- which would put a device
    // called ff:ff:ff:ff:ff:ff in the room. The group check has to come first,
    // and it does.
    TEST_ASSERT_TRUE(macIsRandomised(kBcast));

    StationTable& t = table();
    t.clear();
    TEST_ASSERT_NULL(t.touch(kBcast, -50, 1));
    TEST_ASSERT_EQUAL_UINT8(0, t.count());

    const uint8_t multicast[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};
    TEST_ASSERT_NULL(t.touch(multicast, -50, 1));
    TEST_ASSERT_EQUAL_UINT8(0, t.count());
}

void test_probed_network_names_are_collected_without_duplicates() {
    StationTable& t = table();
    t.clear();
    t.noteProbe(kPhone, "home-wifi", -50, 1);
    t.noteProbe(kPhone, "BA Lounge", -50, 2);
    t.noteProbe(kPhone, "home-wifi", -50, 3);

    TEST_ASSERT_EQUAL_UINT8(2, t.at(0).ssidCount);
    TEST_ASSERT_EQUAL_STRING("home-wifi", t.at(0).ssids[0]);
    TEST_ASSERT_EQUAL_STRING("BA Lounge", t.at(0).ssids[1]);
    TEST_ASSERT_EQUAL_UINT32(3, t.at(0).probes);
}

void test_a_broadcast_probe_is_counted_but_names_nothing() {
    // Both Android and iOS mostly send probes with no SSID. That is the normal
    // case, and storing an empty string would put a blank row on the screen.
    StationTable& t = table();
    t.clear();
    t.noteProbe(kPhone, "", -50, 1);
    t.noteProbe(kPhone, nullptr, -50, 2);

    TEST_ASSERT_EQUAL_UINT8(1, t.count());
    TEST_ASSERT_EQUAL_UINT32(2, t.at(0).probes);
    TEST_ASSERT_EQUAL_UINT8(0, t.at(0).ssidCount);
    TEST_ASSERT_FALSE(t.at(0).hasNamedProbes());
}

void test_the_probe_list_stops_at_its_limit() {
    StationTable& t = table();
    t.clear();
    for (int i = 0; i < 10; i++) {
        char ssid[16];
        std::snprintf(ssid, sizeof(ssid), "net-%d", i);
        t.noteProbe(kPhone, ssid, -50, 1);
    }
    TEST_ASSERT_EQUAL_UINT8(kMaxProbesPerStation, t.at(0).ssidCount);
    TEST_ASSERT_EQUAL_STRING("net-0", t.at(0).ssids[0]);
}

void test_association_records_which_access_point() {
    StationTable& t = table();
    t.clear();
    t.noteAssociation(kPhone, kAp, -50, 1);

    TEST_ASSERT_TRUE(t.at(0).associated);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kAp, t.at(0).bssid, 6);
}

void test_a_group_bssid_is_not_an_association() {
    StationTable& t = table();
    t.clear();
    t.noteAssociation(kPhone, kBcast, -50, 1);
    TEST_ASSERT_EQUAL_UINT8(1, t.count());     // the device is real
    TEST_ASSERT_FALSE(t.at(0).associated);     // its "access point" is not
}

void test_best_rssi_is_held_while_current_follows() {
    StationTable& t = table();
    t.clear();
    t.touch(kPhone, -80, 1);
    t.touch(kPhone, -45, 2);
    t.touch(kPhone, -85, 3);

    TEST_ASSERT_EQUAL_INT8(-85, t.at(0).rssi);
    TEST_ASSERT_EQUAL_INT8(-45, t.at(0).bestRssi);
}

void test_a_full_table_evicts_the_device_heard_longest_ago() {
    // The list should describe the room the operator is standing in now.
    StationTable& t = table();
    t.clear();

    for (int i = 0; i < StationTable::kMaxStations; i++) {
        uint8_t mac[6] = {0x02, 0, 0, 0, 0, static_cast<uint8_t>(i)};
        t.touch(mac, -50, static_cast<uint32_t>(1000 + i));
    }
    TEST_ASSERT_EQUAL_UINT8(StationTable::kMaxStations, t.count());

    const uint8_t fresh[6] = {0x02, 0, 0, 0, 0xFF, 0xFF};
    t.touch(fresh, -50, 9000);
    TEST_ASSERT_EQUAL_UINT8(StationTable::kMaxStations, t.count());
    TEST_ASSERT_EQUAL_UINT32(1, t.dropped());

    // The one first seen (oldest lastSeenMs) is gone; the newcomer is present.
    bool foundFresh = false, foundOldest = false;
    const uint8_t oldest[6] = {0x02, 0, 0, 0, 0, 0};
    for (uint8_t i = 0; i < t.count(); i++) {
        if (macEqual(t.at(i).mac, fresh)) foundFresh = true;
        if (macEqual(t.at(i).mac, oldest)) foundOldest = true;
    }
    TEST_ASSERT_TRUE(foundFresh);
    TEST_ASSERT_FALSE(foundOldest);
}

void test_talkers_counts_only_devices_that_named_something() {
    StationTable& t = table();
    t.clear();
    t.noteProbe(kPhone, "home-wifi", -50, 1);
    t.noteProbe(kRandom, "", -50, 1);

    TEST_ASSERT_EQUAL_UINT8(2, t.count());
    TEST_ASSERT_EQUAL_UINT8(1, t.talkers());
}

int main() {
    UNITY_BEGIN();
    RUN_TEST(test_a_device_is_recorded_once_however_often_it_speaks);
    RUN_TEST(test_randomised_addresses_are_flagged);
    RUN_TEST(test_group_addresses_are_rejected_before_being_classified);
    RUN_TEST(test_probed_network_names_are_collected_without_duplicates);
    RUN_TEST(test_a_broadcast_probe_is_counted_but_names_nothing);
    RUN_TEST(test_the_probe_list_stops_at_its_limit);
    RUN_TEST(test_association_records_which_access_point);
    RUN_TEST(test_a_group_bssid_is_not_an_association);
    RUN_TEST(test_best_rssi_is_held_while_current_follows);
    RUN_TEST(test_a_full_table_evicts_the_device_heard_longest_ago);
    RUN_TEST(test_talkers_counts_only_devices_that_named_something);
    return UNITY_END();
}
