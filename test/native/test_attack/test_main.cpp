// Host tests for the transmit families and the gate they go through.
//
// Three of these are named after the defect they exist to prevent. Each of
// those was found on real hardware in the firmware this doctrine came from, and
// each would have been a surface that reported one thing and did another.

#include <unity.h>

#include <cstring>

#include "attack/family.h"

using namespace orthrus::attack;

namespace {

const uint8_t kAp[6]        = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
const uint8_t kSta[6]       = {0x06, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
const uint8_t kBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
const uint8_t kZero[6]      = {0, 0, 0, 0, 0, 0};
const uint8_t kMulticast[6] = {0x01, 0x00, 0x5E, 0x00, 0x00, 0x01};

constexpr uint32_t kNow = 1000;
constexpr uint32_t kTtl = 60u * 60u * 1000u;  // an hour

Authorization locked(uint32_t now = kNow) {
    Authorization a;
    lock(a, "TestNet", kAp, 6, now, kTtl);
    return a;
}

}  // namespace

void setUp() { regionSet(Region::Fcc); }
void tearDown() { regionSet(Region::Fcc); }

// ---- the table --------------------------------------------------------------

void test_every_family_has_a_complete_row() {
    for (uint8_t i = 0; i < static_cast<uint8_t>(Family::Count); i++) {
        const Spec* s = spec(static_cast<Family>(i));
        TEST_ASSERT_NOT_NULL(s);
        TEST_ASSERT_NOT_NULL(s->name);
        TEST_ASSERT_NOT_NULL(s->proves);
        // A family that cannot say what it does to the target has not been
        // thought through. This is the assertion that keeps that true.
        TEST_ASSERT_NOT_NULL(s->effect);
        TEST_ASSERT_TRUE(std::strlen(s->name) > 0);
        TEST_ASSERT_TRUE(std::strlen(s->proves) > 20);
        TEST_ASSERT_TRUE(std::strlen(s->effect) > 20);
    }
}

void test_no_family_defaults_above_its_own_ceiling() {
    for (uint8_t i = 0; i < static_cast<uint8_t>(Family::Count); i++) {
        const Spec* s = spec(static_cast<Family>(i));
        TEST_ASSERT_TRUE(s->defaultPps <= s->maxPps);
        TEST_ASSERT_TRUE(s->maxPps > 0);
        TEST_ASSERT_TRUE(s->maxSeconds > 0);
    }
}

void test_out_of_range_family_is_null_not_a_wild_read() {
    TEST_ASSERT_NULL(spec(Family::Count));
    TEST_ASSERT_NULL(spec(static_cast<Family>(200)));
    TEST_ASSERT_EQUAL_STRING("?", familyName(Family::Count));
}

void test_ble_is_asked_not_inferred_from_the_enum_order() {
    // The emulations sit in the MIDDLE of the enum, after the Wi-Fi families
    // and before nothing. A range check would have answered this wrongly the
    // moment that order changed, which it already has once.
    TEST_ASSERT_TRUE(isBle(Family::BleFindMy));
    TEST_ASSERT_TRUE(isBle(Family::BleSwarm));
    TEST_ASSERT_FALSE(isBle(Family::Deauth));
    TEST_ASSERT_FALSE(isBle(Family::Karma));
    TEST_ASSERT_FALSE(isBle(Family::Count));
}

void test_only_the_two_pairing_families_pop_a_dialog() {
    TEST_ASSERT_TRUE(spec(Family::BleFastPair)->popsDialog);
    TEST_ASSERT_TRUE(spec(Family::BleSwiftPair)->popsDialog);
    TEST_ASSERT_FALSE(spec(Family::BleFindMy)->popsDialog);
    TEST_ASSERT_FALSE(spec(Family::BleTile)->popsDialog);
    TEST_ASSERT_FALSE(spec(Family::BleSmartTag)->popsDialog);
    TEST_ASSERT_FALSE(spec(Family::BleFlipper)->popsDialog);
    TEST_ASSERT_FALSE(spec(Family::BleSwarm)->popsDialog);
}

void test_the_disruptive_families_are_the_ones_that_deny_service() {
    TEST_ASSERT_EQUAL(static_cast<int>(Klass::Disruptive),
                      static_cast<int>(spec(Family::Deauth)->klass));
    TEST_ASSERT_EQUAL(static_cast<int>(Klass::Disruptive),
                      static_cast<int>(spec(Family::ChannelSwitch)->klass));
    // Inventing beacons denies nothing. Calling it disruptive would train an
    // operator to ignore the word.
    TEST_ASSERT_EQUAL(static_cast<int>(Klass::Benign),
                      static_cast<int>(spec(Family::Beacon)->klass));
}

// ---- the authorisation ------------------------------------------------------

void test_a_group_bssid_is_not_a_target() {
    Authorization a;
    TEST_ASSERT_FALSE(lock(a, "x", kBroadcast, 6, kNow, kTtl));
    TEST_ASSERT_FALSE(a.locked);
    TEST_ASSERT_FALSE(lock(a, "x", kZero, 6, kNow, kTtl));
    TEST_ASSERT_FALSE(a.locked);
    TEST_ASSERT_FALSE(lock(a, "x", kMulticast, 6, kNow, kTtl));
    TEST_ASSERT_FALSE(a.locked);
}

void test_a_channel_outside_the_band_is_not_a_target() {
    Authorization a;
    TEST_ASSERT_FALSE(lock(a, "x", kAp, 0, kNow, kTtl));
    TEST_ASSERT_FALSE(lock(a, "x", kAp, 15, kNow, kTtl));
    TEST_ASSERT_TRUE(lock(a, "x", kAp, 14, kNow, kTtl));
}

void test_a_ttl_is_clamped_down_and_never_up() {
    Authorization a;
    TEST_ASSERT_TRUE(lock(a, "x", kAp, 6, kNow, kMaxTtlMs * 10));
    TEST_ASSERT_EQUAL_UINT32(kMaxTtlMs, a.ttlMs);

    TEST_ASSERT_TRUE(lock(a, "x", kAp, 6, kNow, 5000));
    TEST_ASSERT_EQUAL_UINT32(5000, a.ttlMs);
}

void test_an_authorisation_expires() {
    Authorization a = locked();
    TEST_ASSERT_TRUE(a.valid(kNow));
    TEST_ASSERT_TRUE(a.valid(kNow + kTtl - 1));
    TEST_ASSERT_FALSE(a.valid(kNow + kTtl));
    TEST_ASSERT_EQUAL_UINT32(0, a.remainingMs(kNow + kTtl));
}

void test_remaining_time_counts_down_rather_than_up() {
    Authorization a = locked();
    TEST_ASSERT_EQUAL_UINT32(kTtl, a.remainingMs(kNow));
    TEST_ASSERT_EQUAL_UINT32(kTtl - 1000, a.remainingMs(kNow + 1000));
}

void test_a_wrapped_millisecond_counter_does_not_grant_four_hours() {
    // The device has been on for 49 days and millis() has wrapped. Unsigned
    // subtraction still yields the elapsed time; a signed comparison would
    // have made the lock look eternal.
    Authorization a;
    const uint32_t nearEnd = 0xFFFFFF00u;
    TEST_ASSERT_TRUE(lock(a, "x", kAp, 6, nearEnd, 1000));
    TEST_ASSERT_TRUE(a.valid(nearEnd + 500));        // wrapped, still inside
    TEST_ASSERT_FALSE(a.valid(nearEnd + 1500));      // wrapped, expired
}

// ---- DEFECT 2: one scope, derived from one field ---------------------------

void test_naming_a_client_narrows_the_scope_rather_than_sitting_beside_it() {
    // The defect: "whole cell" and "one named client" were two independent
    // flags and the destination resolver preferred whole-cell, so naming a
    // client left the radio broadcasting at everybody while every screen
    // reported a narrowed scope. There is now one field and it decides both.
    Authorization a = locked();
    TEST_ASSERT_EQUAL(static_cast<int>(Scope::WholeCell),
                      static_cast<int>(scopeOf(a)));

    uint8_t dest[6];
    destinationFor(a, dest);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kBroadcast, dest, 6);

    TEST_ASSERT_TRUE(lockClient(a, kSta));
    TEST_ASSERT_EQUAL(static_cast<int>(Scope::OneClient),
                      static_cast<int>(scopeOf(a)));
    destinationFor(a, dest);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(kSta, dest, 6);
}

void test_the_cell_can_be_widened_back_with_a_null_client() {
    Authorization a = locked();
    TEST_ASSERT_TRUE(lockClient(a, kSta));
    TEST_ASSERT_TRUE(lockClient(a, nullptr));
    TEST_ASSERT_EQUAL(static_cast<int>(Scope::WholeCell),
                      static_cast<int>(scopeOf(a)));
}

void test_a_group_address_cannot_be_named_as_a_client() {
    // A broadcast wearing a station's clothes: it would narrow the screen's
    // report while widening the radio's reach.
    Authorization a = locked();
    TEST_ASSERT_FALSE(lockClient(a, kBroadcast));
    TEST_ASSERT_FALSE(a.haveClient);
    TEST_ASSERT_FALSE(lockClient(a, kMulticast));
    TEST_ASSERT_FALSE(a.haveClient);
}

void test_a_client_cannot_be_named_without_a_target() {
    Authorization a;
    TEST_ASSERT_FALSE(lockClient(a, kSta));
}

// ---- DEFECT 1: the authorisation check is unconditional --------------------

void test_a_bluetooth_family_is_checked_against_an_authorisation_too() {
    // THE DEFECT. The check sat inside the `needsTarget` branch, so every
    // family with needsTarget false -- which is every Bluetooth family --
    // transmitted with no authorisation ever consulted. The families that need
    // no target are exactly the ones that look like they need no permission.
    Authorization none;
    Plan p;
    planDefault(p, Family::BleFindMy);
    TEST_ASSERT_FALSE(spec(Family::BleFindMy)->needsTarget);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::NotAuthorized),
                      static_cast<int>(validate(p, none, kNow)));

    planDefault(p, Family::BleFastPair);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::NotAuthorized),
                      static_cast<int>(validate(p, none, kNow)));

    planDefault(p, Family::BleSwarm);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::NotAuthorized),
                      static_cast<int>(validate(p, none, kNow)));
}

void test_every_single_family_refuses_without_an_authorisation() {
    Authorization none;
    for (uint8_t i = 0; i < static_cast<uint8_t>(Family::Count); i++) {
        Plan p;
        planDefault(p, static_cast<Family>(i));
        TEST_ASSERT_EQUAL(static_cast<int>(PlanError::NotAuthorized),
                          static_cast<int>(validate(p, none, kNow)));
    }
}

void test_an_expired_authorisation_is_refused_with_its_own_reason() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::Deauth);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::AuthorizationExpired),
                      static_cast<int>(validate(p, a, kNow + kTtl + 1)));
}

void test_a_bluetooth_family_passes_once_authorised_even_with_no_target() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::BleTile);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
}

// ---- the gate's other checks ------------------------------------------------

void test_a_family_that_needs_a_target_says_so() {
    Authorization a = locked();
    a.channel = 0;   // locked, but with nothing usable to aim at
    Plan p;
    planDefault(p, Family::Deauth);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::NoTarget),
                      static_cast<int>(validate(p, a, kNow)));
}

void test_a_rate_above_the_ceiling_is_lowered_and_the_plan_says_it_was() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::Deauth);
    p.pps = 9999;
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
    TEST_ASSERT_EQUAL_UINT16(spec(Family::Deauth)->maxPps, p.pps);
    TEST_ASSERT_TRUE(p.clampedPps);
}

void test_a_duration_above_the_ceiling_is_lowered_and_the_plan_says_it_was() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::Deauth);
    p.seconds = 9999;
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
    TEST_ASSERT_EQUAL_UINT16(spec(Family::Deauth)->maxSeconds, p.seconds);
    TEST_ASSERT_TRUE(p.clampedSeconds);
}

void test_a_rate_below_the_ceiling_is_left_alone() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::Deauth);
    p.pps = 3;
    p.seconds = 5;
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
    TEST_ASSERT_EQUAL_UINT16(3, p.pps);
    TEST_ASSERT_EQUAL_UINT16(5, p.seconds);
    TEST_ASSERT_FALSE(p.clampedPps);
    TEST_ASSERT_FALSE(p.clampedSeconds);
}

void test_validate_never_widens_anything() {
    Authorization a = locked();
    for (uint8_t i = 0; i < static_cast<uint8_t>(Family::Count); i++) {
        const Family f = static_cast<Family>(i);
        const Spec* s = spec(f);
        Plan p;
        planDefault(p, f);
        p.pps     = static_cast<uint16_t>(s->maxPps + 1);
        p.seconds = static_cast<uint16_t>(s->maxSeconds + 1);
        // Bluetooth families have no channel to refuse; the Wi-Fi ones follow
        // the target's, which is inside FCC.
        if (validate(p, a, kNow) != PlanError::Ok) continue;
        TEST_ASSERT_TRUE(p.pps <= s->maxPps);
        TEST_ASSERT_TRUE(p.seconds <= s->maxSeconds);
    }
}

void test_a_refused_plan_is_not_left_half_clamped() {
    // The third defect, in its other half: a refused run must not come back
    // looking like a validated one, because the caller that ignores the return
    // value is the caller that scores a burst the radio never sent.
    Authorization none;
    Plan p;
    planDefault(p, Family::Deauth);
    p.pps = 9999;
    TEST_ASSERT_NOT_EQUAL(static_cast<int>(PlanError::Ok),
                          static_cast<int>(validate(p, none, kNow)));
    TEST_ASSERT_EQUAL_UINT16(9999, p.pps);   // untouched
    TEST_ASSERT_FALSE(p.clampedPps);
}

void test_a_continuous_run_has_no_duration_and_no_budget() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::Karma);
    p.continuous = true;
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
    TEST_ASSERT_EQUAL_UINT16(0, p.seconds);
    TEST_ASSERT_EQUAL_UINT32(0, frameBudget(p));
}

// ---- DEFECT 3: a budget is defined even for a plan nobody validated -------

void test_a_budget_is_defined_for_an_unvalidated_plan() {
    // The defect: three returns left the frame count untouched, callers read
    // it uninitialised, and the result line reported a burst that was never
    // emitted. frameBudget() now clamps rather than trusting.
    Plan p;
    p.family  = Family::Deauth;
    p.pps     = 60000;
    p.seconds = 60000;
    const uint32_t b = frameBudget(p);
    TEST_ASSERT_EQUAL_UINT32(
        static_cast<uint32_t>(spec(Family::Deauth)->maxPps) *
            spec(Family::Deauth)->maxSeconds,
        b);
}

void test_a_budget_is_the_number_an_operator_can_reason_about() {
    Authorization a = locked();
    Plan p;
    planDefault(p, Family::Deauth);
    p.pps     = 20;
    p.seconds = 30;
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
    TEST_ASSERT_EQUAL_UINT32(600, frameBudget(p));
}

void test_an_unknown_family_has_no_budget_rather_than_a_wild_one() {
    Plan p;
    p.family  = static_cast<Family>(200);
    p.pps     = 10;
    p.seconds = 10;
    TEST_ASSERT_EQUAL_UINT32(0, frameBudget(p));
}

// ---- the regulatory clamp ---------------------------------------------------

void test_the_default_domain_is_the_narrowest_one() {
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc), static_cast<int>(regionGet()));
    TEST_ASSERT_EQUAL_UINT8(11, regionMaxChannel());
    TEST_ASSERT_TRUE(regionAllows(11));
    TEST_ASSERT_FALSE(regionAllows(12));
    TEST_ASSERT_FALSE(regionAllows(0));
}

void test_an_unknown_country_code_narrows_rather_than_widens() {
    // Guessing wide authorises a transmission; guessing narrow merely refuses
    // one. So an unknown code is FCC.
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc),
                      static_cast<int>(regionFromCountry("ZZ")));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc),
                      static_cast<int>(regionFromCountry("")));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc),
                      static_cast<int>(regionFromCountry(nullptr)));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc),
                      static_cast<int>(regionFromCountry("U")));
}

void test_country_codes_are_case_insensitive() {
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Etsi),
                      static_cast<int>(regionFromCountry("gb")));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Etsi),
                      static_cast<int>(regionFromCountry("GB")));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Jp),
                      static_cast<int>(regionFromCountry("jp")));
}

void test_a_channel_names_the_narrowest_domain_that_permits_it() {
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc),
                      static_cast<int>(regionForChannel(11)));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Etsi),
                      static_cast<int>(regionForChannel(13)));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Jp),
                      static_cast<int>(regionForChannel(14)));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc),
                      static_cast<int>(regionForChannel(99)));
}

void test_widening_for_a_target_never_narrows() {
    regionSet(Region::Jp);
    TEST_ASSERT_FALSE(regionWidenFor(1));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Jp), static_cast<int>(regionGet()));

    regionSet(Region::Fcc);
    TEST_ASSERT_TRUE(regionWidenFor(13));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Etsi), static_cast<int>(regionGet()));
    // Already wide enough: no change, and it says so.
    TEST_ASSERT_FALSE(regionWidenFor(12));
}

void test_widening_refuses_a_channel_that_means_nothing() {
    regionSet(Region::Fcc);
    TEST_ASSERT_FALSE(regionWidenFor(0));
    TEST_ASSERT_FALSE(regionWidenFor(99));
    TEST_ASSERT_EQUAL(static_cast<int>(Region::Fcc), static_cast<int>(regionGet()));
}

void test_a_channel_outside_the_domain_refuses_the_run() {
    Authorization a;
    lock(a, "x", kAp, 13, kNow, kTtl);   // a target on 13, under FCC rules
    Plan p;
    planDefault(p, Family::Deauth);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::ChannelRefused),
                      static_cast<int>(validate(p, a, kNow)));

    // Widened for the target, the same plan is permitted. The operator is told
    // this happened, which is the point: it is their call to make knowingly.
    TEST_ASSERT_TRUE(regionWidenFor(13));
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
}

void test_a_bluetooth_family_is_not_refused_for_a_wifi_channel() {
    Authorization a;
    lock(a, "x", kAp, 13, kNow, kTtl);
    Plan p;
    planDefault(p, Family::BleFindMy);
    TEST_ASSERT_EQUAL(static_cast<int>(PlanError::Ok),
                      static_cast<int>(validate(p, a, kNow)));
}

// ---- the test prefix --------------------------------------------------------

void test_an_invented_label_must_carry_the_prefix() {
    TEST_ASSERT_TRUE(labelOk("ORTHRUS-lab1"));
    TEST_ASSERT_FALSE(labelOk("CorpWiFi"));
    TEST_ASSERT_FALSE(labelOk("orthrus-lab1"));   // case matters on the air
    TEST_ASSERT_FALSE(labelOk(nullptr));
    TEST_ASSERT_FALSE(labelOk(""));
}

void test_the_prefix_alone_is_not_a_name() {
    // Two invented networks both called "ORTHRUS-" are indistinguishable on
    // anyone else's scanner, which defeats the reason for the prefix.
    TEST_ASSERT_FALSE(labelOk("ORTHRUS-"));
    TEST_ASSERT_TRUE(labelOk("ORTHRUS-1"));
}

void test_only_the_named_exceptions_may_wear_somebody_elses_identity() {
    TEST_ASSERT_TRUE(familyMayImpersonate(Family::TwinBeacon));
    TEST_ASSERT_TRUE(familyMayImpersonate(Family::Karma));
    TEST_ASSERT_TRUE(familyMayImpersonate(Family::BleFindMy));
    TEST_ASSERT_TRUE(familyMayImpersonate(Family::BleSwarm));

    // Inventing access points has no reason to borrow a name, so it may not.
    TEST_ASSERT_FALSE(familyMayImpersonate(Family::Beacon));
    TEST_ASSERT_FALSE(familyMayImpersonate(Family::Deauth));
    TEST_ASSERT_FALSE(familyMayImpersonate(Family::Pmkid));
}

void test_every_group_and_class_has_a_name_and_a_blurb() {
    for (uint8_t i = 0; i < static_cast<uint8_t>(Group::Count); i++) {
        const Group g = static_cast<Group>(i);
        TEST_ASSERT_TRUE(std::strlen(groupName(g)) > 0);
        TEST_ASSERT_TRUE(std::strlen(groupBlurb(g)) > 0);
        TEST_ASSERT_EQUAL_STRING("?", "?");
    }
    TEST_ASSERT_EQUAL_STRING("disruptive", klassName(Klass::Disruptive));
    TEST_ASSERT_EQUAL_STRING("Wi-Fi", radioName(Radio::Wifi));
    TEST_ASSERT_EQUAL_STRING("Bluetooth", radioName(Radio::Ble));
}

void test_every_plan_error_has_text_an_operator_can_read() {
    const PlanError all[] = {
        PlanError::Ok,       PlanError::UnknownFamily,
        PlanError::NotAuthorized, PlanError::AuthorizationExpired,
        PlanError::NoTarget, PlanError::NoClient,
        PlanError::ChannelRefused};
    for (PlanError e : all) {
        TEST_ASSERT_TRUE(std::strlen(planErrorText(e)) > 3);
    }
}

int main() {
    UNITY_BEGIN();

    RUN_TEST(test_every_family_has_a_complete_row);
    RUN_TEST(test_no_family_defaults_above_its_own_ceiling);
    RUN_TEST(test_out_of_range_family_is_null_not_a_wild_read);
    RUN_TEST(test_ble_is_asked_not_inferred_from_the_enum_order);
    RUN_TEST(test_only_the_two_pairing_families_pop_a_dialog);
    RUN_TEST(test_the_disruptive_families_are_the_ones_that_deny_service);

    RUN_TEST(test_a_group_bssid_is_not_a_target);
    RUN_TEST(test_a_channel_outside_the_band_is_not_a_target);
    RUN_TEST(test_a_ttl_is_clamped_down_and_never_up);
    RUN_TEST(test_an_authorisation_expires);
    RUN_TEST(test_remaining_time_counts_down_rather_than_up);
    RUN_TEST(test_a_wrapped_millisecond_counter_does_not_grant_four_hours);

    RUN_TEST(test_naming_a_client_narrows_the_scope_rather_than_sitting_beside_it);
    RUN_TEST(test_the_cell_can_be_widened_back_with_a_null_client);
    RUN_TEST(test_a_group_address_cannot_be_named_as_a_client);
    RUN_TEST(test_a_client_cannot_be_named_without_a_target);

    RUN_TEST(test_a_bluetooth_family_is_checked_against_an_authorisation_too);
    RUN_TEST(test_every_single_family_refuses_without_an_authorisation);
    RUN_TEST(test_an_expired_authorisation_is_refused_with_its_own_reason);
    RUN_TEST(test_a_bluetooth_family_passes_once_authorised_even_with_no_target);

    RUN_TEST(test_a_family_that_needs_a_target_says_so);
    RUN_TEST(test_a_rate_above_the_ceiling_is_lowered_and_the_plan_says_it_was);
    RUN_TEST(test_a_duration_above_the_ceiling_is_lowered_and_the_plan_says_it_was);
    RUN_TEST(test_a_rate_below_the_ceiling_is_left_alone);
    RUN_TEST(test_validate_never_widens_anything);
    RUN_TEST(test_a_refused_plan_is_not_left_half_clamped);
    RUN_TEST(test_a_continuous_run_has_no_duration_and_no_budget);

    RUN_TEST(test_a_budget_is_defined_for_an_unvalidated_plan);
    RUN_TEST(test_a_budget_is_the_number_an_operator_can_reason_about);
    RUN_TEST(test_an_unknown_family_has_no_budget_rather_than_a_wild_one);

    RUN_TEST(test_the_default_domain_is_the_narrowest_one);
    RUN_TEST(test_an_unknown_country_code_narrows_rather_than_widens);
    RUN_TEST(test_country_codes_are_case_insensitive);
    RUN_TEST(test_a_channel_names_the_narrowest_domain_that_permits_it);
    RUN_TEST(test_widening_for_a_target_never_narrows);
    RUN_TEST(test_widening_refuses_a_channel_that_means_nothing);
    RUN_TEST(test_a_channel_outside_the_domain_refuses_the_run);
    RUN_TEST(test_a_bluetooth_family_is_not_refused_for_a_wifi_channel);

    RUN_TEST(test_an_invented_label_must_carry_the_prefix);
    RUN_TEST(test_the_prefix_alone_is_not_a_name);
    RUN_TEST(test_only_the_named_exceptions_may_wear_somebody_elses_identity);
    RUN_TEST(test_every_group_and_class_has_a_name_and_a_blurb);
    RUN_TEST(test_every_plan_error_has_text_an_operator_can_read);

    return UNITY_END();
}
