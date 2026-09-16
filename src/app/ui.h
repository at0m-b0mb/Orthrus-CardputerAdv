#pragma once

#include <cstdint>

#include "lorawan/findings.h"
#include "theme.h"

namespace orthrus::ui {

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
// EU868 has 8 default channels and 6 spreading factors -- 48 combinations. One
// SX1262 camps on exactly one. Drawing all 48 cells and lighting one shows the
// size of the blind spot without a word of explanation.
void coverageGrid(int x, int y, uint8_t channels, uint8_t sfs,
                  int litChannel, int litSf);

uint16_t severityColour(lorawan::Severity s);
uint16_t gradeColour(lorawan::Grade g);

// Both take y as the row's CENTRE line, matching the datum used internally.
void textAt(int x, int y, uint16_t colour, const char* fmt, ...);
void textRight(int rightEdge, int y, uint16_t colour, const char* fmt, ...);

// Word-wrapped body text. Breaks on spaces, never mid-word, and stops at
// maxLines rather than running off the panel. Returns the y below the last
// line drawn, so callers can lay out what follows.
//
// A finding without its explanation is just an accusation, and the lower half
// of the dossier is exactly where the explanation belongs.
int wrapText(int x, int y, int maxWidth, int lineHeight, int maxLines,
             uint16_t colour, const char* text);

}  // namespace orthrus::ui
