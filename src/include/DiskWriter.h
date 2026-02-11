#pragma once
#include <fstream>
#include <iostream>
#include <filesystem>
#include <vector>
#include <mutex>
#include <json.hpp>

struct FileEntry {
    std::string path;     // full path (output_path + name)
    uint64_t length;      // file size
    uint64_t offset;      // global offset in torrent
    std::fstream stream;  // opened file stream
};

class DiskWriter {

private:

    nlohmann::json torrent;
    std::string output_path;
    std::vector<FileEntry> files;
    uint64_t pieceLength;
    std::mutex diskMutex;
    void prepareFile(FileEntry& fe);

public:

    DiskWriter(const nlohmann::json& torrent_data,
        const std::string& out);

    bool WritePiece(int pieceIndex,
        const char* buffer,
        size_t bufferSize);


};