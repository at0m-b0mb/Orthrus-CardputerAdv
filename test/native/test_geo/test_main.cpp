// Host tests for position formatting and accuracy estimates.

#include <unity.h>

#include <cmath>
#include <cstring>

#include "geo/position.h"

using namespace orthrus::geo;

void setUp() {}
void tearDown() {}

// ---- degrees, minutes, seconds ----------------------------------------------

void test_dms_formats_a_northern_latitude() {
    char out[32];
    TEST_ASSERT_TRUE(formatDms(51.507351, true, out, sizeof(out), "d") > 0);
    TEST_ASSERT_EQUAL_STRING("51d30'26.5\"N", out);
}

void test_dms_uses_the_hemisphere_letter_not_a_minus_sign() {
    // A leading minus and a trailing S both mean south, and mixing them is how
    // a position ends up in the wrong hemisphere when somebody retypes it.
    char out[32];
    TEST_ASSERT_TRUE(formatDms(-33.868820, true, out, sizeof(out), "d") > 0);
    TEST_ASSERT_EQUAL_STRING("33d52'07.8\"S", out);
    TEST_ASSERT_NULL(std::strchr(out, '-'));

    TEST_ASSERT_TRUE(formatDms(-0.127758, false, out, sizeof(out), "d") > 0);
    TEST_ASSERT_EQUAL_STRING("0d07'39.9\"W", out);
}

void test_dms_rounding_carries_into_minutes() {
    // 59.96 seconds prints as "60.0" at one decimal place. Nobody writes that
    // down, and a reader who does gets a minute that does not exist.
    char out[32];
    const double deg = 10.0 + (30.0 / 60.0) + (59.97 / 3600.0);
    TEST_ASSERT_TRUE(formatDms(deg, true, out, sizeof(out), "d") > 0);
    TEST_ASSERT_EQUAL_STRING("10d31'00.0\"N", out);
}

void test_dms_rounding_carries_all_the_way_into_degrees() {
    char out[32];
    const double deg = 10.0 + (59.0 / 60.0) + (59.99 / 3600.0);
    TEST_ASSERT_TRUE(formatDms(deg, true, out, sizeof(out), "d") > 0);
    TEST_ASSERT_EQUAL_STRING("11d00'00.0\"N", out);
}

void test_dms_pads_minutes_and_seconds() {
    // Unpadded fields make two positions of the same length look different and
    // are miserable to read down a column.
    char out[32];
    TEST_ASSERT_TRUE(formatDms(1.0 + 2.0 / 60.0 + 3.0 / 3600.0, true, out,
                               sizeof(out), "d") > 0);
    TEST_ASSERT_EQUAL_STRING("1d02'03.0\"N", out);
}

void test_dms_rejects_out_of_range_and_non_finite_values() {
    char out[32];
    TEST_ASSERT_EQUAL_size_t(0, formatDms(91.0, true, out, sizeof(out), "d"));
    TEST_ASSERT_EQUAL_STRING("", out);
    TEST_ASSERT_EQUAL_size_t(0, formatDms(181.0, false, out, sizeof(out), "d"));
    TEST_ASSERT_EQUAL_size_t(0, formatDms(NAN, true, out, sizeof(out), "d"));
    TEST_ASSERT_EQUAL_size_t(0, formatDms(INFINITY, true, out, sizeof(out), "d"));

    // 180 exactly is a real longitude and must survive.
    TEST_ASSERT_TRUE(formatDms(180.0, false, out, sizeof(out), "d") > 0);
}

void test_dms_that_does_not_fit_writes_nothing() {
    char small[8];
    TEST_ASSERT_EQUAL_size_t(0, formatDms(51.507351, true, small, sizeof(small), "d"));
    TEST_ASSERT_EQUAL_STRING("", small);
}

// ---- geometry and error ------------------------------------------------------

void test_geometry_bands_match_the_conventional_ones() {
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Ideal),
                      static_cast<int>(geometryFor(0.8)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Excellent),
                      static_cast<int>(geometryFor(1.5)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Good),
                      static_cast<int>(geometryFor(3.0)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Moderate),
                      static_cast<int>(geometryFor(7.0)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Poor),
                      static_cast<int>(geometryFor(15.0)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Unusable),
                      static_cast<int>(geometryFor(40.0)));
}

void test_absent_hdop_is_unknown_and_not_perfect() {
    // A receiver that has not reported HDOP yet reports 0. Reading that as
    // "zero dilution" would show an ideal fix to somebody standing indoors.
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Unknown),
                      static_cast<int>(geometryFor(0.0)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Unknown),
                      static_cast<int>(geometryFor(-1.0)));
    TEST_ASSERT_EQUAL(static_cast<int>(Geometry::Unknown),
                      static_cast<int>(geometryFor(NAN)));
    TEST_ASSERT_EQUAL_UINT16(0, estimatedErrorMeters(0.0));
    TEST_ASSERT_EQUAL_UINT16(0, estimatedErrorMeters(NAN));
}

void test_error_estimate_never_goes_below_the_receivers_own_floor() {
    // Perfect geometry does not make a consumer receiver better than the chip
    // it is built on. An estimate under the UERE would be a promise the
    // hardware cannot keep.
    TEST_ASSERT_EQUAL_UINT16(5, estimatedErrorMeters(0.5));
    TEST_ASSERT_EQUAL_UINT16(5, estimatedErrorMeters(0.9));
}

void test_error_estimate_rounds_up() {
    // 1.1 * 5 = 5.5 metres. Rounding that down to 5 quotes a radius that
    // sometimes excludes the true position.
    TEST_ASSERT_EQUAL_UINT16(6, estimatedErrorMeters(1.1));
    TEST_ASSERT_EQUAL_UINT16(10, estimatedErrorMeters(2.0));
    TEST_ASSERT_EQUAL_UINT16(9999, estimatedErrorMeters(100000.0));
}

// ---- distance ----------------------------------------------------------------

void test_distance_between_known_points() {
    // King's Cross to Waterloo, about 3.0 km as the crow flies.
    const double m = distanceMeters(51.5308, -0.1238, 51.5031, -0.1132);
    TEST_ASSERT_TRUE(m > 2800.0);
    TEST_ASSERT_TRUE(m < 3300.0);
}

void test_distance_to_self_is_zero() {
    TEST_ASSERT_TRUE(distanceMeters(51.5, -0.12, 51.5, -0.12) < 0.001);
}

void test_distance_works_across_the_antimeridian() {
    // Haversine takes the short way round on its own; a naive difference of
    // longitudes would call these two points most of the way round the world.
    const double m = distanceMeters(0.0, 179.99, 0.0, -179.99);
    TEST_ASSERT_TRUE(m < 3000.0);
}

// ---- plausibility ------------------------------------------------------------

void test_null_island_is_not_a_fix() {
    // Exactly (0, 0) is almost always a struct nobody filled in, and a false
    // pin on a client's map is worse than a missing one.
    TEST_ASSERT_FALSE(plausible(0.0, 0.0));
    TEST_ASSERT_TRUE(plausible(0.0001, 0.0));
    TEST_ASSERT_TRUE(plausible(51.5, -0.12));
}

void test_out_of_range_positions_are_refused() {
    TEST_ASSERT_FALSE(plausible(90.1, 0.0));
    TEST_ASSERT_FALSE(plausible(0.0, 180.1));
    TEST_ASSERT_FALSE(plausible(NAN, 0.0));
    TEST_ASSERT_TRUE(plausible(90.0, 180.0));
}

// -----------------------------------------------------------------------------

int main() {
    UNITY_BEGIN();

    RUN_TEST(test_dms_formats_a_northern_latitude);
    RUN_TEST(test_dms_uses_the_hemisphere_letter_not_a_minus_sign);
    RUN_TEST(test_dms_rounding_carries_into_minutes);
    RUN_TEST(test_dms_rounding_carries_all_the_way_into_degrees);
    RUN_TEST(test_dms_pads_minutes_and_seconds);
    RUN_TEST(test_dms_rejects_out_of_range_and_non_finite_values);
    RUN_TEST(test_dms_that_does_not_fit_writes_nothing);

    RUN_TEST(test_geometry_bands_match_the_conventional_ones);
    RUN_TEST(test_absent_hdop_is_unknown_and_not_perfect);
    RUN_TEST(test_error_estimate_never_goes_below_the_receivers_own_floor);
    RUN_TEST(test_error_estimate_rounds_up);

    RUN_TEST(test_distance_between_known_points);
    RUN_TEST(test_distance_to_self_is_zero);
    RUN_TEST(test_distance_works_across_the_antimeridian);

    RUN_TEST(test_null_island_is_not_a_fix);
    RUN_TEST(test_out_of_range_positions_are_refused);

    return UNITY_END();
}
