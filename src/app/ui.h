#pragma once

#include <cstdint>

#include "lorawan/findings.h"
#include "theme.h"

namespace orthrus::ui {

// Header rule and title. `right` is optional status text, drawn brass.
void chrome(const char* title, const char* right = nullptr);

// Footer hint line. Keep it to what is not obvious.
void footer(const char* hint);

// The signature element: the band we can actually hear.
//
// EU868 has 8 default channels and 6 spreading factors -- 48 combinations. One
// SX1262 camps on exactly one of them. Drawing all 48 cells with a single one
// lit is the most honest thing this device does: the operator can see the size
// of the blind spot without reading a word of documentation.
void coverageGrid(int x, int y, uint8_t channels, uint8_t sfs,
                  int litChannel, int litSf);

uint16_t severityColour(lorawan::Severity s);
uint16_t gradeColour(lorawan::Grade g);

// Right-aligned helper, because signal figures read better flush right.
void textRight(int rightEdge, int y, uint16_t colour, const char* fmt, ...);

}  // namespace orthrus::ui
