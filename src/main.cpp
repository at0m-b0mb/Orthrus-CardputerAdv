// Orthrus -- multi-surface red team platform for the M5Stack Cardputer-Adv.
//
// Authorized testing only. The engagement record is not decoration: it is what
// makes a capture a client deliverable rather than an anecdote.
//
// THE MENU IS TWO LEVELS, ON PURPOSE
//
// A flat list worked at four surfaces and was already scrolling at seven. The
// thing an operator actually knows when they pick the device up is which RADIO
// they are about to point at something -- Wi-Fi, infrared, the LoRa cap -- so
// that is the first choice, and it is a grid of nine tiles that all fit on one
// screen with no scrolling at all. What lives inside a category is the second
// choice, by which point the list is two or three items long.

#include <M5Cardputer.h>

#include <cstdio>

#include "app/icons.h"
#include "app/theme.h"
#include "app/ui.h"
#include "hal/board.h"
#include "hal/hid.h"
#include "modules/airspace.h"
#include "modules/control.h"
#include "modules/credentials.h"
#include "modules/engagement.h"
#include "modules/harvest.h"
#include "modules/instruments.h"
#include "modules/keys.h"
#include "modules/payload.h"
#include "modules/perimeter.h"
#include "modules/position.h"
#include "modules/proximity.h"

using namespace orthrus::theme;
namespace bd = orthrus::board;
namespace ic = orthrus::icons;

namespace {

constexpr char kVersion[] = "1.1.0";

// The Cardputer's printed arrow keys.
constexpr char kKeyUp    = ';';
constexpr char kKeyDown  = '.';
constexpr char kKeyLeft  = ',';
constexpr char kKeyRight = '/';
constexpr char kKeyBack  = '`';

// ---- what the device can do -------------------------------------------------

enum class Tool : uint8_t {
    Perimeter = 0,
    Harvest,
    Proximity,
    Credentials,
    Keys,
    Control,
    Airspace,
    Position,
    Payload,
    Engagement,
    Instruments,
};

struct ToolEntry {
    Tool        tool;
    const char* name;
    const char* blurb;
    bool        ready;
};

struct Category {
    const char*      name;
    ic::Glyph        glyph;
    const ToolEntry* tools;
    uint8_t          count;
};

const ToolEntry kWifiTools[] = {
    {Tool::Perimeter, "Perimeter", "Survey, graded and mapped",     true},
    {Tool::Harvest,   "Harvest",   "WPA handshake and PMKID capture", true},
};

const ToolEntry kBluetoothTools[] = {
    {Tool::Proximity, "Proximity", "BLE device and tracker recon", true},
};

const ToolEntry kNfcTools[] = {
    {Tool::Credentials, "Credentials", "13.56 MHz badge identify and grade", true},
};

const ToolEntry kRfidTools[] = {
    {Tool::Keys, "Keys", "Mifare Classic sector key sweep", true},
};

const ToolEntry kInfraredTools[] = {
    {Tool::Control, "Control", "Room control, onboard emitter", true},
};

const ToolEntry kLoraTools[] = {
    {Tool::Airspace, "Airspace", "LoRa and LoRaWAN device census", true},
};

const ToolEntry kGpsTools[] = {
    {Tool::Position, "Position", "Live fix, waypoints and track log", true},
};

const ToolEntry kUsbTools[] = {
    {Tool::Payload, "Payload", "USB keyboard scripts from the card", true},
};

const ToolEntry kSystemTools[] = {
    {Tool::Engagement,  "Engagement",  "Evidence log, chain head, export", true},
    {Tool::Instruments, "Instruments", "Live power, radio, GNSS and tilt", true},
};

#define CAT(arr) arr, static_cast<uint8_t>(sizeof(arr) / sizeof(arr[0]))

// Nine categories, three by three. That is not a coincidence: nine is what fits
// on a 240 x 135 panel without scrolling, and a launcher that scrolls is a
// launcher the operator has to read rather than recognise.
const Category kCategories[] = {
    {"Wi-Fi",     ic::Glyph::Wifi,      CAT(kWifiTools)},
    {"Bluetooth", ic::Glyph::Bluetooth, CAT(kBluetoothTools)},
    {"NFC",       ic::Glyph::Nfc,       CAT(kNfcTools)},
    {"RFID",      ic::Glyph::Rfid,      CAT(kRfidTools)},
    {"Infrared",  ic::Glyph::Infrared,  CAT(kInfraredTools)},
    {"LoRa",      ic::Glyph::Lora,      CAT(kLoraTools)},
    {"GPS",       ic::Glyph::Gps,       CAT(kGpsTools)},
    {"USB",       ic::Glyph::Usb,       CAT(kUsbTools)},
    {"System",    ic::Glyph::System,    CAT(kSystemTools)},
};
constexpr int kCategoryCount = sizeof(kCategories) / sizeof(kCategories[0]);

#undef CAT

// ---- grid geometry ----------------------------------------------------------
//
// Worked out against the panel rather than guessed, because the last layout
// that was guessed ran its bottom row behind the footer.
//   header rule 16 | grid 20..119 | footer rule 123
constexpr int kCols     = 3;
constexpr int kGridRows = 3;
constexpr int kTileW    = bd::kScreenW / kCols;   // 80
constexpr int kTileH    = 33;
constexpr int kGridTop  = 20;
constexpr int kIconDy   = 13;   // icon centre, from the tile's top
constexpr int kLabelDy  = 27;   // label centre, from the tile's top

// ---- list geometry (second level) ------------------------------------------
constexpr int kListTop    = 21;
constexpr int kListRowH   = 14;
constexpr int kListRows   = 6;
constexpr int kDetailRule = 107;

enum class Level : uint8_t { Grid, List };

Level g_level    = Level::Grid;
int   g_category = 0;
int   g_tool     = 0;

const Category& category() { return kCategories[g_category]; }

// ---- splash -----------------------------------------------------------------

void drawSplash() {
    orthrus::ui::beginFrame();
    auto& d = orthrus::ui::gfx();

    d.setFont(kFaceIdentity);
    d.setTextDatum(middle_center);
    d.setTextColor(kText, kInk);
    d.drawString("ORTHRUS", bd::kScreenW / 2, 44);

    d.drawFastHLine(bd::kScreenW / 2 - 52, 58, 104, kShine);

    d.setFont(kFaceData);
    d.setTextColor(kBrass, kInk);
    d.drawString("multi-surface red team platform", bd::kScreenW / 2, 72);

    d.setTextColor(kFaint, kInk);
    d.drawString("authorized testing only", bd::kScreenW / 2, 86);

    char ver[24];
    std::snprintf(ver, sizeof(ver), "v%s", kVersion);
    d.setTextColor(kFaint, kInk);
    d.drawString(ver, bd::kScreenW / 2, 104);

    d.setTextDatum(top_left);
    orthrus::ui::endFrame();
}

// ---- level 0: the category grid --------------------------------------------

void drawGrid() {
    orthrus::ui::beginFrame();
    auto& d = orthrus::ui::gfx();

    char batt[12];
    std::snprintf(batt, sizeof(batt), "%d%%", M5.Power.getBatteryLevel());
    orthrus::ui::chrome("Orthrus", batt);

    for (int i = 0; i < kCategoryCount; i++) {
        const int col = i % kCols;
        const int row = i / kCols;
        if (row >= kGridRows) break;

        const int x = col * kTileW;
        const int y = kGridTop + row * kTileH;
        const int cx = x + kTileW / 2;
        const bool sel = (i == g_category);

        uint16_t bg = kInk;
        if (sel) {
            // A raised panel with a gold edge, matching the list selection
            // elsewhere. Bright gold cannot carry text, so it draws the border
            // and never the fill.
            bg = kSurface;
            d.fillRoundRect(x + 2, y + 1, kTileW - 4, kTileH - 3, 3, kSurface);
            d.drawRoundRect(x + 2, y + 1, kTileW - 4, kTileH - 3, 3, kShine);
        }

        ic::draw(kCategories[i].glyph, cx, y + kIconDy, sel ? kShine : kBrass, bg);

        d.setFont(kFaceData);
        d.setTextDatum(middle_center);
        d.setTextColor(sel ? kText : kMuted, bg);
        d.drawString(kCategories[i].name, cx, y + kLabelDy);
    }

    d.setTextDatum(top_left);
    orthrus::ui::footer("; . , /  move    enter  open");
    orthrus::ui::endFrame();
}

// ---- level 1: the tools inside one category --------------------------------

void drawList() {
    orthrus::ui::beginFrame();
    auto& d = orthrus::ui::gfx();

    const Category& c = category();

    char right[16];
    std::snprintf(right, sizeof(right), "%u tool%s", static_cast<unsigned>(c.count),
                  c.count == 1 ? "" : "s");
    orthrus::ui::chrome(c.name, right);

    if (g_tool >= c.count) g_tool = c.count - 1;
    if (g_tool < 0) g_tool = 0;

    for (int row = 0; row < kListRows && row < c.count; row++) {
        const int y   = kListTop + row * kListRowH;
        const int mid = y + kListRowH / 2;
        const bool sel = (row == g_tool);

        orthrus::ui::listRow(y, kListRowH, sel);

        d.setFont(kFaceUi);
        d.setTextDatum(middle_left);
        d.setTextColor(c.tools[row].ready ? kText : kFaint, sel ? kSurface : kInk);
        d.drawString(c.tools[row].name, 10, mid);

        if (!c.tools[row].ready) {
            d.setFont(kFaceData);
            d.setTextDatum(middle_right);
            d.setTextColor(kFaint, sel ? kSurface : kInk);
            d.drawString("soon", bd::kScreenW - 6, mid);
        }
    }

    orthrus::ui::detailStrip(kDetailRule, c.tools[g_tool].blurb);
    orthrus::ui::footer("; . move   enter open   ` back");
    d.setTextDatum(top_left);
    orthrus::ui::endFrame();
}

void draw() {
    if (g_level == Level::Grid) drawGrid();
    else                        drawList();
}

// ---- shared dead ends -------------------------------------------------------

void waitForKey() {
    for (;;) {
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed())
            return;
        delay(10);
    }
}

void notReady(const ToolEntry& t) {
    orthrus::ui::beginFrame();
    auto& d = orthrus::ui::gfx();
    orthrus::ui::chrome(t.name);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kMuted, kInk);
    d.drawString("Not built yet.", 8, kHeaderH + 14);
    d.setTextColor(kText, kInk);
    d.drawString(t.blurb, 8, kHeaderH + 32);

    d.setTextColor(kFaint, kInk);
    d.drawString("Shipping it empty would be", 8, kHeaderH + 54);
    d.drawString("worse than saying so.", 8, kHeaderH + 66);

    orthrus::ui::footer("any key   back");
    orthrus::ui::endFrame();
    waitForKey();
}

void failure(const char* title, const char* l1, const char* l2, const char* l3) {
    orthrus::ui::beginFrame();
    auto& d = orthrus::ui::gfx();
    orthrus::ui::chrome(title);

    d.setFont(kFaceData);
    d.setTextDatum(top_left);
    d.setTextColor(kCritical, kInk);
    d.drawString(l1, 8, kHeaderH + 16);
    d.setTextColor(kMuted, kInk);
    if (l2) d.drawString(l2, 8, kHeaderH + 34);
    if (l3) d.drawString(l3, 8, kHeaderH + 46);

    orthrus::ui::footer("any key   back");
    orthrus::ui::endFrame();
    waitForKey();
}

// ---- opening a tool ---------------------------------------------------------

void openTool(const ToolEntry& entry) {
    if (!entry.ready) {
        notReady(entry);
        return;
    }

    switch (entry.tool) {
        case Tool::Airspace: {
            // Static: the census table is ~13 KB and has no business on the
            // loop task's 8 KB stack.
            static orthrus::modules::Airspace airspace;
            if (!airspace.begin()) {
                failure("Airspace", "Radio did not start.",
                        "Check the LoRa cap is seated",
                        "and the antenna is fitted.");
                return;
            }
            airspace.run();
            return;
        }

        case Tool::Perimeter: {
            static orthrus::modules::Perimeter perimeter;
            perimeter.begin();
            perimeter.run();
            return;
        }

        case Tool::Harvest: {
            // Static: the target table is ~7 KB, for the same reason Airspace
            // is static.
            static orthrus::modules::Harvest harvest;
            if (!harvest.begin()) {
                failure("Harvest", "Monitor mode did not start.",
                        "The Wi-Fi radio refused promiscuous",
                        "mode. Power cycle and try again.");
                return;
            }
            harvest.run();
            return;
        }

        case Tool::Proximity: {
            static orthrus::modules::Proximity proximity;
            if (!proximity.begin()) {
                failure("Proximity", "Bluetooth did not start.",
                        "The BLE stack refused to come up.",
                        "Power cycle and try again.");
                return;
            }
            proximity.run();
            return;
        }

        case Tool::Credentials: {
            static orthrus::modules::Credentials credentials;
            if (!credentials.begin()) {
                failure("Credentials", "No reader found.",
                        "Plug an RFID2 unit into either",
                        "Grove port: board or LoRa cap.");
                return;
            }
            credentials.run();
            return;
        }

        case Tool::Keys: {
            static orthrus::modules::Keys keys;
            if (!keys.begin()) {
                failure("Keys", "No reader found.",
                        "Plug an RFID2 unit into either",
                        "Grove port: board or LoRa cap.");
                return;
            }
            keys.run();
            return;
        }

        case Tool::Control: {
            static orthrus::modules::Control control;
            control.begin();
            control.run();
            return;
        }

        case Tool::Position: {
            static orthrus::modules::Position position;
            position.begin();
            position.run();
            return;
        }

        case Tool::Engagement: {
            static orthrus::modules::Engagement engagement;
            engagement.begin();
            engagement.run();
            return;
        }

        case Tool::Payload: {
            static orthrus::modules::Payload payload;
            payload.begin();
            payload.run();
            return;
        }

        case Tool::Instruments: {
            static orthrus::modules::Instruments instruments;
            instruments.begin();
            instruments.run();
            return;
        }

        default:
            notReady(entry);
            return;
    }
}

// ---- input ------------------------------------------------------------------

void moveGrid(int dCol, int dRow) {
    int col = g_category % kCols;
    int row = g_category / kCols;

    col += dCol;
    row += dRow;

    // Clamp rather than wrap. Wrapping on a nine-tile grid means a slip of the
    // thumb lands three categories away, and the operator has to re-read the
    // whole screen to find out where they are.
    if (col < 0) col = 0;
    if (col >= kCols) col = kCols - 1;
    if (row < 0) row = 0;

    int target = row * kCols + col;
    if (target >= kCategoryCount) {
        // The last row may be short. Step back onto the final tile rather than
        // off the end of the table.
        if (dRow > 0) return;
        target = kCategoryCount - 1;
    }
    g_category = target;
}

void handleKey(char c) {
    if (g_level == Level::Grid) {
        switch (c) {
            case kKeyUp:    moveGrid(0, -1); break;
            case kKeyDown:  moveGrid(0, +1); break;
            case kKeyLeft:  moveGrid(-1, 0); break;
            case kKeyRight: moveGrid(+1, 0); break;
            default: return;
        }
        draw();
        return;
    }

    switch (c) {
        case kKeyUp:
            if (g_tool > 0) { g_tool--; draw(); }
            break;
        case kKeyDown:
            if (g_tool + 1 < category().count) { g_tool++; draw(); }
            break;
        case kKeyBack:
        case kKeyLeft:
            g_level = Level::Grid;
            draw();
            break;
        default:
            break;
    }
}

void handleEnter() {
    if (g_level == Level::Grid) {
        // A category with exactly one tool opens it directly. Making the
        // operator confirm a list of one is pure ceremony.
        if (category().count == 1) {
            openTool(category().tools[0]);
            draw();
            return;
        }
        g_level = Level::List;
        g_tool  = 0;
        draw();
        return;
    }

    openTool(category().tools[g_tool]);
    draw();
}

}  // namespace

void setup() {
    // HID first, before anything else touches USB.
    //
    // A USB device's interfaces are fixed at enumeration. Registering the
    // keyboard later -- when the operator opens the Payload screen -- is too
    // late: the host has already decided this is a serial port only, and no
    // keyboard ever appears. Measured, not assumed: doing it lazily produced a
    // CDC with no HID interface at all.
    //
    // On builds without HID this is a no-op, so the default firmware is
    // unchanged.
    if (orthrus::hal::hidSupportedInBuild()) orthrus::hal::sharedHid().begin();

    auto cfg = M5.config();
    M5Cardputer.begin(cfg, true);
    M5Cardputer.Display.setRotation(1);
    Serial.begin(115200);

    const uint32_t heapBefore = ESP.getFreeHeap();
    drawSplash();
    // Worth stating out loud: if the frame buffer could not be allocated the
    // device still works, but it flickers, and that should be diagnosable
    // without guessing.
    Serial.printf("[orthrus] heap %u -> %u, double-buffered=%s\n",
                  static_cast<unsigned>(heapBefore),
                  static_cast<unsigned>(ESP.getFreeHeap()),
                  (heapBefore - ESP.getFreeHeap()) > 50000 ? "yes" : "NO");

    const uint32_t deadline = millis() + 6000;
    for (;;) {
        M5Cardputer.update();
        if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) break;
        if (millis() > deadline) break;
        delay(10);
    }
    draw();
}

void loop() {
    M5Cardputer.update();

    if (M5Cardputer.Keyboard.isChange() && M5Cardputer.Keyboard.isPressed()) {
        const auto ks = M5Cardputer.Keyboard.keysState();
        if (ks.enter) {
            handleEnter();
        } else {
            for (char c : ks.word) handleKey(c);
        }
    }
    delay(10);
}
