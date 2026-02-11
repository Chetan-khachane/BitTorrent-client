#pragma once

#include <string>
#include <vector>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <json.hpp>
#include <DiskWriter.h>
#include <TorrentManager.h>

using json = nlohmann::json;

class TorrentDownloader {

private:
    std::string output_path;
    SOCKET clientSocket = INVALID_SOCKET;
    json torrentFile;

 
    std::vector<uint8_t> message_builder(
        uint8_t id,
        const std::vector<uint8_t>& payload
    );

    bool send_all(const void* buffer, size_t len);
    bool recv_all(void* buffer, size_t bytes);

    std::shared_ptr<TorrentStatus> torrentStatus;
    std::vector<bool> peerBitfield;

public:
    TorrentDownloader(
        const std::string& path,
        json torrent,
        DiskWriter& DiskWriterManager,
        std::shared_ptr<TorrentStatus> TorrentStatus
    );

    DiskWriter& DiskManager;

    void setClientSocket(SOCKET& sock);

    bool waitForUnchoke();
    void handleBitField(int payload_length);
    void handleHave();

    std::vector<bool> getBitField();
    bool downloadOnePiece(int index);
};
