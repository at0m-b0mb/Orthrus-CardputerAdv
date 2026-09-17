#pragma once

#include <M5Cardputer.h>

#include <cstdint>

#include "credential/grade.h"
#include "lorawan/findings.h"
#include "theme.h"

namespace orthrus::ui {

// Draw target.
//
// Screens are composed off-screen and pushed in one go. Drawing straight to the
// panel meant every redraw began with a full fillScreen, and at ~5 frames a
// second that is visible flicker on an SPI display -- the single most obvious
// defect on the first hardware build.
//
// If the 65 KB sprite cannot be allocated, gfx() falls back to the panel and
// everything still works, just with the flicker. Degrading is better than
// refusing to draw.
LovyanGFX& gfx();

// Clears the frame. Returns true when double buffering is active.
bool beginFrame();

// Pushes the composed frame to the panel.
void endFrame();

// Header: section name in the identity face, optional status flush right, and
// the one gold rule in the product.
void chrome(const char* title, const char* right = nullptr);

// Footer hint line, drawn on the bottom rule.
void footer(const char* hint);

// Selection band for a list row: surface fill plus a gold edge.
void listRow(int y, int height, bool selected);

// A single explanatory line under a list, for the selected item only. Keeping
// the description out of every row is what lets the rows breathe on a 135 px
// panel.
void detailStrip(int y, const char* text);

// The signature element: the band we can actually hear.
//
// Draws every channel/SF cell and lights the one being listened to, so the size
// of the blind spot is visible without a word of explanation. Cell size adapts
// to fit `maxWidth`, because US915 sweeps twice as many channels as EU868 and a
// fixed cell size ran the grid off the edge of the panel.
//
// Returns the y coordinate just below the grid.
int coverageGrid(int x, int y, uint8_t cols, uint8_t rows, int litCol, int litRow,
                 int maxWidth);

uint16_t severityColour(lorawan::Severity s);
uint16_t gradeColour(lorawan::Grade g);

// Separate overloads rather than casting between the two namespaces' enums.
// They line up today by coincidence, not by contract, and a cast would go
// silently wrong the moment either gains a value.
uint16_t severityColour(credential::Severity s);
uint16_t gradeColour(credential::Grade g);

// Both take y as the row's CENTRE line, matching the datum used internally.
void textAt(int x, int y, uint16_t colour, const char* fmt, ...);
void textRight(int rightEdge, int y, uint16_t colour, const char* fmt, ...);

// Word-wrapped body text. Breaks on spaces, never mid-word, and stops at
// maxLines rather than running off the panel. Returns the y below the last
// line drawn.
//
// A finding without its explanation is just an accusation, and the lower half
// of the dossier is exactly where the explanation belongs.
int wrapText(int x, int y, int maxWidth, int lineHeight, int maxLines,
             uint16_t colour, const char* text);

}  // namespace orthrus::ui
