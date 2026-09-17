// Files: what is actually on the card.
//
// Every surface here writes something -- session logs, hash files, packet
// captures, card dumps -- and until now the only way to check any of it was to
// power the device down and find a card reader. That is a bad moment to
// discover an export never happened.
//
// READ ONLY, AND THAT IS A DECISION
//
// There is no delete. An engagement log that can be erased in the field is not
// evidence, and a device that offers the operator a way to quietly remove a
// capture is a device whose logs a client has no reason to trust. Pull the card
// out and use a computer; that leaves a trace this does not.

#pragma once

#include <cstddef>
#include <cstdint>

namespace orthrus::modules {

class SysFiles {
public:
    bool begin();
    void run();

private:
    enum class View : uint8_t { List, Preview, NoCard };

    static constexpr uint8_t  kMaxEntries = 40;
    static constexpr uint8_t  kNameLen    = 40;
    static constexpr uint16_t kPathLen    = 96;
    // How much of a file to read for the preview. Enough to see whether an
    // export worked; small enough that opening a ten megabyte capture does not
    // stall the UI.
    static constexpr uint16_t kPreviewBytes = 1024;

    struct Entry {
        char     name[kNameLen] = {0};
        uint32_t size  = 0;
        bool     isDir = false;
    };

    void scan();
    void descend(const Entry& e);
    void ascend();
    void openPreview(const Entry& e);

    void drawList();
    void drawPreview();
    void drawNoCard();
    bool handleKeys();

    static bool looksTextual(const char* name);

    // Joins a directory and a name, refusing rather than truncating. Returns
    // false when the result would not fit.
    static bool joinPath(const char* dir, const char* name, char* out, size_t cap);

    char    path_[kPathLen] = "/";
    Entry   entries_[kMaxEntries];
    uint8_t count_    = 0;
    int     selected_ = 0;
    int     scroll_   = 0;
    bool    truncated_ = false;   // more entries than the table holds

    char     preview_[kPreviewBytes + 1] = {0};
    uint16_t previewLen_ = 0;
    bool     previewText_ = false;
    uint32_t previewSize_ = 0;
    int      previewLine_ = 0;
    char     previewName_[kNameLen] = {0};

    View     view_       = View::List;
    uint32_t lastDrawMs_ = 0;
};

}  // namespace orthrus::modules
