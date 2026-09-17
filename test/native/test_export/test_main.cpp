// Host tests for evidence export.
//
// The important ones are hostile: detail strings come off the air, so a device
// that names itself "</name><Placemark>" must not be able to inject structure
// into an exported KML, and a payload fragment containing a comma must not be
// able to shift a CSV column.

#include <unity.h>

#include <algorithm>
#include <cstring>
#include <string>

#include "evidence/chain.h"
#include "evidence/export.h"

using namespace orthrus::evidence;

namespace {

Record rec(uint32_t seq, RecordKind kind, const char* detail) {
    Record r;
    r.seq    = seq;
    r.timeMs = seq * 1000;
    r.kind   = kind;
    std::snprintf(r.detail, kDetailLen, "%s", detail);
    return r;
}

std::string esc(const char* in, size_t cap = 512) {
    std::string buf(cap, '\0');
    escapeXml(in, buf.data(), cap);
    return std::string(buf.c_str());
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- XML escaping -----------------------------------------------------------

void test_escapes_all_five_xml_entities() {
    TEST_ASSERT_EQUAL_STRING("&amp;", esc("&").c_str());
    TEST_ASSERT_EQUAL_STRING("&lt;", esc("<").c_str());
    TEST_ASSERT_EQUAL_STRING("&gt;", esc(">").c_str());
    TEST_ASSERT_EQUAL_STRING("&quot;", esc("\"").c_str());
    TEST_ASSERT_EQUAL_STRING("&apos;", esc("'").c_str());
}

void test_plain_text_passes_through() {
    TEST_ASSERT_EQUAL_STRING("26011BDA rssi=-78", esc("26011BDA rssi=-78").c_str());
}

void test_control_characters_are_dropped() {
    // A stray control byte makes some XML parsers reject the whole document.
    // Dropping beats shipping a file that will not open.
    TEST_ASSERT_EQUAL_STRING("ab", esc("a\x01\x02\x1F" "b").c_str());
}

void test_escaping_truncates_without_overrunning() {
    char out[8];
    const size_t n = escapeXml("&&&&&&&&&&", out, sizeof(out));
    TEST_ASSERT_TRUE(n <= sizeof(out) - 1);
    TEST_ASSERT_TRUE(std::strlen(out) < sizeof(out));
}

void test_escape_handles_null_and_zero_cap() {
    char out[4];
    TEST_ASSERT_EQUAL_UINT32(0, escapeXml(nullptr, out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("", out);
    TEST_ASSERT_EQUAL_UINT32(0, escapeXml("x", out, 0));
}

// ---- the injection that matters ---------------------------------------------

void test_kml_injection_attempt_is_neutralised() {
    // A device naming itself with KML structure. If this lands unescaped the
    // exported file gains a placemark the operator never recorded.
    const Record r = rec(1, RecordKind::Device,
                         "dev=</name><Placemark><name>GHOST rssi=-40");
    Position p;
    p.valid = true;
    p.lat = 51.5074;
    p.lon = -0.1278;

    char out[2048];
    const size_t n = kmlPlacemark(out, sizeof(out), r, p);
    TEST_ASSERT_TRUE(n > 0);

    const std::string s(out);
    // Exactly one placemark opened, and no raw injected tag survived.
    TEST_ASSERT_EQUAL_UINT32(1, static_cast<uint32_t>(
        [&] { size_t c = 0, i = 0;
              while ((i = s.find("<Placemark>", i)) != std::string::npos) { c++; i++; }
              return c; }()));
    TEST_ASSERT_TRUE(s.find("</name><Placemark><name>GHOST") == std::string::npos);
    TEST_ASSERT_TRUE(s.find("&lt;Placemark&gt;") != std::string::npos);
}

void test_kml_coordinates_are_longitude_first() {
    // KML is lon,lat. Getting it the usual way round puts London in Somalia,
    // and it is the single most common mistake in KML exporters.
    const Record r = rec(2, RecordKind::Device, "dev=ABCD lat=51.5074 lon=-0.1278");
    const Position p = positionOf(r);
    TEST_ASSERT_TRUE(p.valid);

    char out[1024];
    kmlPlacemark(out, sizeof(out), r, p);
    TEST_ASSERT_TRUE(std::string(out).find("-0.127800,51.507400,0") != std::string::npos);
}

void test_placemark_skipped_without_a_position() {
    const Record r = rec(3, RecordKind::Device, "dev=ABCD rssi=-90");
    Position p;  // invalid
    char out[512];
    TEST_ASSERT_EQUAL_UINT32(0, kmlPlacemark(out, sizeof(out), r, p));
}

// ---- field parsing ----------------------------------------------------------

void test_field_lookup_respects_token_boundaries() {
    char v[16];
    // "lat" must not match inside "flat".
    TEST_ASSERT_FALSE(findField("flat=9 x=1", "lat", v, sizeof(v)));
    TEST_ASSERT_TRUE(findField("flat=9 lat=51.5", "lat", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("51.5", v);
}

void test_field_lookup_at_start_and_end() {
    char v[16];
    TEST_ASSERT_TRUE(findField("dev=AABB rssi=-70", "dev", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("AABB", v);
    TEST_ASSERT_TRUE(findField("dev=AABB rssi=-70", "rssi", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("-70", v);
}

void test_missing_field_reports_missing() {
    char v[16];
    TEST_ASSERT_FALSE(findField("dev=AABB", "lat", v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("", v);
}

void test_null_gps_island_is_refused() {
    // 0,0 is in the Gulf of Guinea and is almost always an uninitialised
    // struct. A map full of placemarks there is worse than no map.
    TEST_ASSERT_FALSE(positionOf(rec(1, RecordKind::Device,
                                     "dev=X lat=0 lon=0")).valid);
    TEST_ASSERT_FALSE(positionOf(rec(1, RecordKind::Device,
                                     "dev=X lat=0.000000 lon=0.000000")).valid);
}

void test_out_of_range_coordinates_refused() {
    TEST_ASSERT_FALSE(positionOf(rec(1, RecordKind::Device,
                                     "lat=91 lon=10")).valid);
    TEST_ASSERT_FALSE(positionOf(rec(1, RecordKind::Device,
                                     "lat=10 lon=181")).valid);
    TEST_ASSERT_TRUE(positionOf(rec(1, RecordKind::Device,
                                    "lat=-33.8688 lon=151.2093")).valid);
}

void test_non_numeric_coordinates_refused() {
    TEST_ASSERT_FALSE(positionOf(rec(1, RecordKind::Device,
                                     "lat=north lon=east")).valid);
}

// ---- CSV --------------------------------------------------------------------

void test_csv_quotes_and_doubles_embedded_quotes() {
    const Record r = rec(4, RecordKind::Note, "he said \"hello\"");
    char out[512];
    TEST_ASSERT_TRUE(csvRow(out, sizeof(out), r, nullptr) > 0);
    TEST_ASSERT_TRUE(std::string(out).find("\"he said \"\"hello\"\"\"") != std::string::npos);
}

void test_csv_comma_in_detail_does_not_shift_columns() {
    const Record r = rec(5, RecordKind::Device, "dev=AA,BB rssi=-70");
    char out[512];
    csvRow(out, sizeof(out), r, nullptr);

    // Five fields, and the comma inside the quoted detail must not create a
    // sixth. Count only the commas outside quotes.
    const std::string s(out);
    int depth = 0, fields = 1;
    for (char c : s) {
        if (c == '"') depth = !depth;
        else if (c == ',' && !depth) fields++;
    }
    TEST_ASSERT_EQUAL_INT(5, fields);
}

void test_csv_row_includes_digest() {
    uint8_t digest[orthrus::crypto::kSha256DigestLen];
    for (size_t i = 0; i < sizeof(digest); i++) digest[i] = static_cast<uint8_t>(i);
    const Record r = rec(6, RecordKind::Finding, "dev=AA grade=F");
    char out[512];
    csvRow(out, sizeof(out), r, digest);
    TEST_ASSERT_TRUE(std::string(out).find("000102030405") != std::string::npos);
}

void test_csv_reports_overflow_rather_than_truncating() {
    const Record r = rec(7, RecordKind::Device, "dev=AABBCCDD rssi=-70 grade=F");
    char tiny[8];
    TEST_ASSERT_EQUAL_UINT32(0, csvRow(tiny, sizeof(tiny), r, nullptr));
}

void test_csv_header_shape() {
    char out[128];
    TEST_ASSERT_TRUE(csvHeader(out, sizeof(out)) > 0);
    TEST_ASSERT_EQUAL_STRING("seq,time_ms,kind,detail,digest\n", out);
}

// ---- document structure -----------------------------------------------------

void test_kml_document_opens_and_closes() {
    char head[1024], foot[128];
    TEST_ASSERT_TRUE(kmlHeader(head, sizeof(head), "site A survey") > 0);
    TEST_ASSERT_TRUE(kmlFooter(foot, sizeof(foot)) > 0);

    const std::string h(head), f(foot);
    TEST_ASSERT_TRUE(h.find("<kml") != std::string::npos);
    TEST_ASSERT_TRUE(h.find("<Document>") != std::string::npos);
    TEST_ASSERT_TRUE(h.find("site A survey") != std::string::npos);
    TEST_ASSERT_TRUE(f.find("</Document>") != std::string::npos);
    TEST_ASSERT_TRUE(f.find("</kml>") != std::string::npos);
}

void test_kml_title_is_escaped_too() {
    char head[1024];
    kmlHeader(head, sizeof(head), "a & b <c>");
    const std::string h(head);
    TEST_ASSERT_TRUE(h.find("a &amp; b &lt;c&gt;") != std::string::npos);
    TEST_ASSERT_TRUE(h.find("<c>") == std::string::npos);
}

void test_csv_field_reads_plain_and_quoted() {
    const char* line = "3,4000,device,\"dev=AA,BB rssi=-70\",abcdef\n";
    char v[64];
    TEST_ASSERT_TRUE(csvField(line, 0, v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("3", v);
    TEST_ASSERT_TRUE(csvField(line, 2, v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("device", v);
    // The comma inside the quoted detail must not split it.
    TEST_ASSERT_TRUE(csvField(line, 3, v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("dev=AA,BB rssi=-70", v);
    TEST_ASSERT_TRUE(csvField(line, 4, v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("abcdef", v);
}

void test_csv_field_unescapes_doubled_quotes() {
    const char* line = "1,2,note,\"he said \"\"hi\"\"\",dd\n";
    char v[64];
    TEST_ASSERT_TRUE(csvField(line, 3, v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING("he said \"hi\"", v);
}

void test_csv_field_round_trips_what_csvRow_wrote() {
    // The property that matters: anything the device writes, it can read back.
    const Record r = rec(9, RecordKind::Device, "dev=AA,\"BB lat=1.5 lon=2.5");
    char line[512];
    csvRow(line, sizeof(line), r, nullptr);

    char v[160];
    TEST_ASSERT_TRUE(csvField(line, 3, v, sizeof(v)));
    TEST_ASSERT_EQUAL_STRING(r.detail, v);
}

void test_csv_field_past_the_end_reports_false() {
    char v[32];
    TEST_ASSERT_FALSE(csvField("a,b,c", 9, v, sizeof(v)));
}

// ---- regression: control bytes cannot break the file format ----------------

void test_newline_in_detail_cannot_split_a_record() {
    // THE regression. A fuzzer found this: a detail string containing a newline
    // ended the CSV record half way through, so the rest of it masqueraded as a
    // new row, the chain stopped verifying against the file, and a crafted
    // payload could inject lines that read as genuine records.
    const Record r = rec(1, RecordKind::Device,
                         "dev=AA\n99,0,device,\"INJECTED\",deadbeef");
    char out[512];
    TEST_ASSERT_TRUE(csvRow(out, sizeof(out), r, nullptr) > 0);

    const std::string s(out);
    // Exactly one line ending, at the very end.
    TEST_ASSERT_EQUAL_UINT32(1, static_cast<uint32_t>(
        std::count(s.begin(), s.end(), '\n')));
    TEST_ASSERT_EQUAL_CHAR('\n', s.back());
}

void test_carriage_return_also_neutralised() {
    const Record r = rec(2, RecordKind::Note, "a\rb\tc");
    char out[512];
    csvRow(out, sizeof(out), r, nullptr);
    const std::string s(out);
    TEST_ASSERT_TRUE(s.find('\r') == std::string::npos);
    TEST_ASSERT_TRUE(s.find('\t') == std::string::npos);
}

void test_sanitise_is_idempotent() {
    // Applied at both the record and formatting layers, so it must be, or the
    // chain digest and the bytes on the card would disagree.
    char once[64], twice[64];
    sanitiseText("a\nb\x01" "c", once, sizeof(once));
    sanitiseText(once, twice, sizeof(twice));
    TEST_ASSERT_EQUAL_STRING(once, twice);
    TEST_ASSERT_EQUAL_STRING("a b c", once);
}

void test_sanitise_preserves_printable_text() {
    char out[64];
    sanitiseText("dev=AABB lat=51.5 lon=-0.1", out, sizeof(out));
    TEST_ASSERT_EQUAL_STRING("dev=AABB lat=51.5 lon=-0.1", out);
}

void test_sanitise_bounds() {
    char out[4];
    TEST_ASSERT_EQUAL_UINT32(3, sanitiseText("abcdefgh", out, sizeof(out)));
    TEST_ASSERT_EQUAL_STRING("abc", out);
    TEST_ASSERT_EQUAL_UINT32(0, sanitiseText("x", out, 0));
    TEST_ASSERT_EQUAL_UINT32(0, sanitiseText(nullptr, out, sizeof(out)));
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_escapes_all_five_xml_entities);
    RUN_TEST(test_plain_text_passes_through);
    RUN_TEST(test_control_characters_are_dropped);
    RUN_TEST(test_escaping_truncates_without_overrunning);
    RUN_TEST(test_escape_handles_null_and_zero_cap);

    RUN_TEST(test_kml_injection_attempt_is_neutralised);
    RUN_TEST(test_kml_coordinates_are_longitude_first);
    RUN_TEST(test_placemark_skipped_without_a_position);

    RUN_TEST(test_field_lookup_respects_token_boundaries);
    RUN_TEST(test_field_lookup_at_start_and_end);
    RUN_TEST(test_missing_field_reports_missing);
    RUN_TEST(test_null_gps_island_is_refused);
    RUN_TEST(test_out_of_range_coordinates_refused);
    RUN_TEST(test_non_numeric_coordinates_refused);

    RUN_TEST(test_csv_quotes_and_doubles_embedded_quotes);
    RUN_TEST(test_csv_comma_in_detail_does_not_shift_columns);
    RUN_TEST(test_csv_row_includes_digest);
    RUN_TEST(test_csv_reports_overflow_rather_than_truncating);
    RUN_TEST(test_csv_header_shape);

    RUN_TEST(test_kml_document_opens_and_closes);
    RUN_TEST(test_kml_title_is_escaped_too);

    RUN_TEST(test_csv_field_reads_plain_and_quoted);
    RUN_TEST(test_csv_field_unescapes_doubled_quotes);
    RUN_TEST(test_csv_field_round_trips_what_csvRow_wrote);
    RUN_TEST(test_csv_field_past_the_end_reports_false);

    RUN_TEST(test_newline_in_detail_cannot_split_a_record);
    RUN_TEST(test_carriage_return_also_neutralised);
    RUN_TEST(test_sanitise_is_idempotent);
    RUN_TEST(test_sanitise_preserves_printable_text);
    RUN_TEST(test_sanitise_bounds);

    return UNITY_END();
}
