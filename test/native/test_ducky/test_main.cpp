// Host tests for the HID keymap and DuckyScript parser.
//
// These matter more than most. A wrong keycode does not crash -- it types a
// different character into somebody's machine, and the first you know of it is
// a payload that did not work and a command history that says something else.

#include <unity.h>

#include <cstdio>
#include <cstring>
#include <string>

#include "ducky/keymap.h"
#include "ducky/script.h"

using namespace orthrus::ducky;

namespace {

ParsedLine parse(const char* s) {
    ParsedLine p;
    parseLine(s, p);
    return p;
}

std::string textOf(const ParsedLine& p) {
    return p.text ? std::string(p.text, p.textLen) : std::string();
}

}  // namespace

void setUp() {}
void tearDown() {}

// ---- keymap -----------------------------------------------------------------

void test_lowercase_letters_map_contiguously() {
    // HID puts 'a' at 0x04 and runs to 'z' at 0x1D. An off-by-one here shifts
    // the entire alphabet.
    for (char c = 'a'; c <= 'z'; c++) {
        const KeyStroke k = keyForChar(c);
        TEST_ASSERT_TRUE(k.valid());
        TEST_ASSERT_EQUAL_UINT8(0x04 + (c - 'a'), k.keycode);
        TEST_ASSERT_EQUAL_UINT8(0, k.modifiers);
    }
    TEST_ASSERT_EQUAL_UINT8(0x1D, keyForChar('z').keycode);
}

void test_uppercase_is_the_same_key_plus_shift() {
    for (char c = 'A'; c <= 'Z'; c++) {
        const KeyStroke k = keyForChar(c);
        TEST_ASSERT_TRUE(k.valid());
        TEST_ASSERT_EQUAL_UINT8(keyForChar(static_cast<char>(c + 32)).keycode,
                                k.keycode);
        TEST_ASSERT_EQUAL_UINT8(kModShift, k.modifiers);
    }
}

void test_digits_put_zero_last() {
    // HID orders them '1'..'9' then '0', which is the trap: '0' is 0x27, not
    // 0x1D, and getting it wrong types a 9 wherever a 0 was meant.
    TEST_ASSERT_EQUAL_UINT8(0x1E, keyForChar('1').keycode);
    TEST_ASSERT_EQUAL_UINT8(0x26, keyForChar('9').keycode);
    TEST_ASSERT_EQUAL_UINT8(0x27, keyForChar('0').keycode);
}

void test_shifted_punctuation_uses_the_right_base_key() {
    struct { char shifted; char base; } pairs[] = {
        {'!', '1'}, {'@', '2'}, {'#', '3'}, {'$', '4'}, {'%', '5'},
        {'^', '6'}, {'&', '7'}, {'*', '8'}, {'(', '9'}, {')', '0'},
        {'_', '-'}, {'+', '='}, {'{', '['}, {'}', ']'}, {'|', '\\'},
        {':', ';'}, {'"', '\''}, {'~', '`'}, {'<', ','}, {'>', '.'},
        {'?', '/'},
    };
    for (const auto& p : pairs) {
        const KeyStroke s = keyForChar(p.shifted);
        const KeyStroke b = keyForChar(p.base);
        TEST_ASSERT_TRUE(s.valid());
        TEST_ASSERT_TRUE(b.valid());
        TEST_ASSERT_EQUAL_UINT8(b.keycode, s.keycode);
        TEST_ASSERT_EQUAL_UINT8(kModShift, s.modifiers);
        TEST_ASSERT_EQUAL_UINT8(0, b.modifiers);
    }
}

void test_every_printable_ascii_is_typeable() {
    // A payload is mostly ASCII. Anything in this range we cannot type would
    // be silently missing from a command.
    for (char c = 0x20; c < 0x7F; c++) {
        const KeyStroke k = keyForChar(c);
        if (!k.valid()) {
            char msg[64];
            std::snprintf(msg, sizeof(msg), "cannot type 0x%02X '%c'",
                          static_cast<unsigned>(c), c);
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

void test_untypeable_characters_are_refused_not_guessed() {
    // Accented and non-ASCII characters have no US keycode. Substituting the
    // nearest letter would put the wrong text in a command.
    TEST_ASSERT_FALSE(keyForChar(static_cast<char>(0xE9)).valid());  // e-acute
    TEST_ASSERT_FALSE(keyForChar(static_cast<char>(0x01)).valid());
    char bad = 0;
    TEST_ASSERT_FALSE(canTypeAll("caf\xE9", 4, &bad));
    TEST_ASSERT_EQUAL_UINT8(0xE9, static_cast<uint8_t>(bad));
    TEST_ASSERT_TRUE(canTypeAll("powershell -enc AAA==", 21, &bad));
}

void test_named_keys_and_function_keys() {
    TEST_ASSERT_EQUAL_UINT8(kKeyEnter, keycodeForName("ENTER"));
    TEST_ASSERT_EQUAL_UINT8(kKeyEnter, keycodeForName("enter"));
    TEST_ASSERT_EQUAL_UINT8(kKeyDelete, keycodeForName("DELETE"));
    TEST_ASSERT_EQUAL_UINT8(kKeyDown, keycodeForName("DOWNARROW"));
    TEST_ASSERT_EQUAL_UINT8(0x3A, keycodeForName("F1"));
    TEST_ASSERT_EQUAL_UINT8(0x45, keycodeForName("F12"));
    TEST_ASSERT_EQUAL_UINT8(kKeyNone, keycodeForName("F13"));
    TEST_ASSERT_EQUAL_UINT8(kKeyNone, keycodeForName("F0"));
    TEST_ASSERT_EQUAL_UINT8(kKeyNone, keycodeForName("WINKEY"));
}

void test_modifier_names() {
    TEST_ASSERT_EQUAL_UINT8(kModGui, modifierForName("GUI"));
    TEST_ASSERT_EQUAL_UINT8(kModGui, modifierForName("WINDOWS"));
    TEST_ASSERT_EQUAL_UINT8(kModGui, modifierForName("command"));
    TEST_ASSERT_EQUAL_UINT8(kModCtrl, modifierForName("CONTROL"));
    TEST_ASSERT_EQUAL_UINT8(kModAlt, modifierForName("ALT"));
    TEST_ASSERT_EQUAL_UINT8(0, modifierForName("ENTER"));
}

// ---- parser -----------------------------------------------------------------

void test_blank_and_comment_lines() {
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Empty),
                      static_cast<int>(parse("").kind));
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Empty),
                      static_cast<int>(parse("    \t  ").kind));
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Comment),
                      static_cast<int>(parse("REM open a shell").kind));
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Comment),
                      static_cast<int>(parse("rem lowercase too").kind));
    TEST_ASSERT_TRUE(isNoop(parse("REM x").kind));
}

void test_string_keeps_case_and_spacing() {
    // The single most important parser property: a password or a base64 blob
    // must survive byte for byte. Uppercasing it would be memorable.
    const auto p = parse("STRING Hello World  MiXeD  $ymb0l$!");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::String), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_STRING("Hello World  MiXeD  $ymb0l$!", textOf(p).c_str());
}

void test_string_consumes_exactly_one_separating_space() {
    // "STRING  x" means a leading space is part of the text.
    TEST_ASSERT_EQUAL_STRING(" x", textOf(parse("STRING  x")).c_str());
    TEST_ASSERT_EQUAL_STRING("x", textOf(parse("STRING x")).c_str());
}

void test_empty_string_line_is_still_a_string() {
    const auto p = parse("STRING");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::String), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT16(0, p.textLen);
}

void test_stringln_is_distinct_from_string() {
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::StringLn),
                      static_cast<int>(parse("STRINGLN whoami").kind));
    TEST_ASSERT_EQUAL_STRING("whoami", textOf(parse("STRINGLN whoami")).c_str());
}

void test_string_strips_the_line_ending_only() {
    TEST_ASSERT_EQUAL_STRING("abc", textOf(parse("STRING abc\r\n")).c_str());
}

void test_delay_parsing_and_bad_numbers() {
    const auto d = parse("DELAY 500");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Delay), static_cast<int>(d.kind));
    TEST_ASSERT_EQUAL_UINT32(500, d.number);

    // A delay that parses as zero would run the payload at full speed against
    // a machine that was not ready, so it is an error instead.
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Unknown),
                      static_cast<int>(parse("DELAY soon").kind));
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Unknown),
                      static_cast<int>(parse("DELAY 100x").kind));
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Unknown),
                      static_cast<int>(parse("DELAY").kind));
}

void test_huge_delay_clamps_rather_than_wrapping() {
    const auto d = parse("DELAY 99999999999999");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Delay), static_cast<int>(d.kind));
    TEST_ASSERT_EQUAL_UINT32(0xFFFFFFFFu, d.number);
}

void test_default_delay_both_spellings() {
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::DefaultDelay),
                      static_cast<int>(parse("DEFAULTDELAY 20").kind));
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::DefaultDelay),
                      static_cast<int>(parse("DEFAULT_DELAY 20").kind));
    TEST_ASSERT_EQUAL_UINT32(20, parse("DEFAULT_DELAY 20").number);
}

void test_repeat() {
    const auto r = parse("REPEAT 5");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Repeat), static_cast<int>(r.kind));
    TEST_ASSERT_EQUAL_UINT32(5, r.number);
}

// ---- key combinations -------------------------------------------------------

void test_single_named_key() {
    const auto p = parse("ENTER");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Keys), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT8(kKeyEnter, p.keycode);
    TEST_ASSERT_EQUAL_UINT8(0, p.modifiers);
}

void test_gui_r_is_the_classic_run_dialog() {
    const auto p = parse("GUI r");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Keys), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT8(kModGui, p.modifiers);
    TEST_ASSERT_EQUAL_UINT8(keyForChar('r').keycode, p.keycode);
}

void test_single_letter_keeps_its_case() {
    // GUI R and GUI r are different keystrokes to the host: the capital adds
    // shift. Uppercasing every token would silently change the payload.
    const auto lower = parse("GUI r");
    const auto upper = parse("GUI R");
    TEST_ASSERT_EQUAL_UINT8(lower.keycode, upper.keycode);
    TEST_ASSERT_EQUAL_UINT8(kModGui, lower.modifiers);
    TEST_ASSERT_EQUAL_UINT8(kModGui | kModShift, upper.modifiers);
}

void test_multiple_modifiers_combine() {
    const auto p = parse("CTRL ALT DELETE");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Keys), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT8(kModCtrl | kModAlt, p.modifiers);
    TEST_ASSERT_EQUAL_UINT8(kKeyDelete, p.keycode);
}

void test_modifier_only_line_is_valid() {
    const auto p = parse("SHIFT");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Keys), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT8(kModShift, p.modifiers);
    TEST_ASSERT_EQUAL_UINT8(kKeyNone, p.keycode);
}

void test_two_real_keys_is_rejected() {
    // The host receives one key plus modifiers, not two keys. Accepting this
    // would send only one of them and quietly drop the other.
    const auto p = parse("ENTER TAB");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Unknown), static_cast<int>(p.kind));
}

void test_unknown_word_is_reported_with_the_word() {
    // "Line 14: WINKEY" is actionable; "parse error" is not.
    const auto p = parse("WINKEY r");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Unknown), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_STRING("WINKEY", p.unknownWord);
}

void test_leading_whitespace_is_tolerated() {
    const auto p = parse("    GUI r");
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Keys), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT8(kModGui, p.modifiers);
}

void test_null_line_is_safe() {
    ParsedLine p;
    parseLine(nullptr, p);
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Empty), static_cast<int>(p.kind));
}

void test_very_long_word_does_not_overflow() {
    std::string huge(500, 'X');
    const auto p = parse(huge.c_str());
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::Unknown), static_cast<int>(p.kind));
    TEST_ASSERT_TRUE(std::strlen(p.unknownWord) < kMaxWordLen);
}

void test_very_long_string_is_kept_whole() {
    // A base64 blob can be hundreds of characters and must not be truncated by
    // the parser; only the runner's buffer limits it.
    std::string line = "STRING " + std::string(400, 'A');
    const auto p = parse(line.c_str());
    TEST_ASSERT_EQUAL(static_cast<int>(LineKind::String), static_cast<int>(p.kind));
    TEST_ASSERT_EQUAL_UINT16(400, p.textLen);
}

void test_kind_names_present() {
    for (int i = 0; i <= static_cast<int>(LineKind::Unknown); i++)
        TEST_ASSERT_TRUE(std::strlen(lineKindName(static_cast<LineKind>(i))) > 0);
}

// ---- a realistic payload ----------------------------------------------------

void test_a_whole_payload_parses() {
    const char* script[] = {
        "REM demo payload",
        "DEFAULTDELAY 20",
        "DELAY 1000",
        "GUI r",
        "DELAY 500",
        "STRING notepad.exe",
        "ENTER",
        "DELAY 1500",
        "STRINGLN Authorized test. Nothing was changed.",
        "CTRL s",
    };
    const LineKind expect[] = {
        LineKind::Comment, LineKind::DefaultDelay, LineKind::Delay,
        LineKind::Keys, LineKind::Delay, LineKind::String, LineKind::Keys,
        LineKind::Delay, LineKind::StringLn, LineKind::Keys,
    };
    for (size_t i = 0; i < sizeof(script) / sizeof(script[0]); i++) {
        const auto p = parse(script[i]);
        if (p.kind != expect[i]) {
            char msg[96];
            std::snprintf(msg, sizeof(msg), "line %u '%s' parsed as %s",
                          static_cast<unsigned>(i), script[i],
                          lineKindName(p.kind));
            TEST_FAIL_MESSAGE(msg);
        }
    }
}

int main(int, char**) {
    UNITY_BEGIN();

    RUN_TEST(test_lowercase_letters_map_contiguously);
    RUN_TEST(test_uppercase_is_the_same_key_plus_shift);
    RUN_TEST(test_digits_put_zero_last);
    RUN_TEST(test_shifted_punctuation_uses_the_right_base_key);
    RUN_TEST(test_every_printable_ascii_is_typeable);
    RUN_TEST(test_untypeable_characters_are_refused_not_guessed);
    RUN_TEST(test_named_keys_and_function_keys);
    RUN_TEST(test_modifier_names);

    RUN_TEST(test_blank_and_comment_lines);
    RUN_TEST(test_string_keeps_case_and_spacing);
    RUN_TEST(test_string_consumes_exactly_one_separating_space);
    RUN_TEST(test_empty_string_line_is_still_a_string);
    RUN_TEST(test_stringln_is_distinct_from_string);
    RUN_TEST(test_string_strips_the_line_ending_only);
    RUN_TEST(test_delay_parsing_and_bad_numbers);
    RUN_TEST(test_huge_delay_clamps_rather_than_wrapping);
    RUN_TEST(test_default_delay_both_spellings);
    RUN_TEST(test_repeat);

    RUN_TEST(test_single_named_key);
    RUN_TEST(test_gui_r_is_the_classic_run_dialog);
    RUN_TEST(test_single_letter_keeps_its_case);
    RUN_TEST(test_multiple_modifiers_combine);
    RUN_TEST(test_modifier_only_line_is_valid);
    RUN_TEST(test_two_real_keys_is_rejected);
    RUN_TEST(test_unknown_word_is_reported_with_the_word);
    RUN_TEST(test_leading_whitespace_is_tolerated);
    RUN_TEST(test_null_line_is_safe);
    RUN_TEST(test_very_long_word_does_not_overflow);
    RUN_TEST(test_very_long_string_is_kept_whole);
    RUN_TEST(test_kind_names_present);

    RUN_TEST(test_a_whole_payload_parses);

    return UNITY_END();
}
