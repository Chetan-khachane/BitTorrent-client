#include <TorrentDownloader.h>
#include <DiskWriter.h>
#include <btcli.h>
#include <iostream>
#include <vector>
#include <cstring>
#include <mutex>
#include <winsock2.h>
#include <bencrypt.h>
using json = nlohmann::json;

/* MESSAGE BUILDER
/*
 BitTorrent rule:
 <length> = 1 + payload.size()

*/
std::vector<uint8_t> TorrentDownloader::message_builder(
    uint8_t id,
    const std::vector<uint8_t>& payload
) {
    std::vector<uint8_t> message;

    uint32_t total_len = htonl(1 + payload.size());
    message.resize(4);
    std::memcpy(message.data(), &total_len, 4);

    message.push_back(id);
    message.insert(message.end(), payload.begin(), payload.end());

    return message;
}

//SOCKET HELPERS

bool TorrentDownloader::send_all(const void* buffer, size_t len) {
    size_t sent = 0;
    const char* buf = static_cast<const char*>(buffer);

    while (sent < len) {
        int n = send(clientSocket, buf + sent, (int)(len - sent), 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool TorrentDownloader::recv_all(void* buffer, size_t len) {
    size_t recvd = 0;
    char* buf = static_cast<char*>(buffer);

    while (recvd < len) {
        int n = recv(clientSocket, buf + recvd, (int)(len - recvd), 0);
        if (n <= 0) return false;
        recvd += n;
    }
    return true;
}

/*  BITFIELD  */

void TorrentDownloader::handleBitField(int payload_length) {
    std::vector<uint8_t> payload(payload_length);
    recv_all(payload.data(), payload_length);

    size_t totalPieces =
        torrentFile["info"]["pieces"].get<std::string>().size() / 20;

    if (peerBitfield.empty())
        peerBitfield.assign(totalPieces, false);

    for (int byte = 0; byte < payload_length; byte++) {
        for (int bit = 0; bit < 8; bit++) {
            int piece = byte * 8 + bit;
            if (piece >= (int)totalPieces) return;

            if (payload[byte] & (1 << (7 - bit)))
                peerBitfield[piece] = true;
        }
    }
}

/*  HAVE  */

void TorrentDownloader::handleHave() {
    uint32_t piece;
    recv_all(&piece, 4);
    piece = ntohl(piece);

    if (piece < peerBitfield.size())
        peerBitfield[piece] = true;
}

/* UNCHOKE + BITFIELD WAIT  */

bool TorrentDownloader::waitForUnchoke() {

    // Send INTERESTED
    auto interested = message_builder(2, {});
    if (!send_all(interested.data(), interested.size()))
        return false;

    bool unchoked = false;

    while (true) {

        uint32_t net_len;
        if (!recv_all(&net_len, 4))
            return false;

        uint32_t msg_len = ntohl(net_len);
        if (msg_len == 0)
            continue; // keep-alive

        uint8_t msg_id;
        if (!recv_all(&msg_id, 1))
            return false;

        switch (msg_id) {

        case 1: // UNCHOKE
            unchoked = true;
            break;

        case 0: // CHOKE
            return false;

        case 4: // HAVE
            handleHave();
            break;

        case 5: // BITFIELD
            handleBitField(msg_len - 1);
            break;

        default:
            if (msg_len > 1) {
                std::vector<uint8_t> skip(msg_len - 1);
                recv_all(skip.data(), skip.size());
            }
            break;
        }

        //  wait for BOTH unchoke + bitfield
        if (unchoked && !peerBitfield.empty())
            return true;
    }
}

/*  PIECE VERIFY  */

static bool verifyPieceHash(
    int pieceIndex,
    const std::vector<uint8_t>& buffer,
    const json& torrent
) {
    const std::string& pieces =
        torrent["info"]["pieces"].get<std::string>();

    const uint8_t* expected =
        reinterpret_cast<const uint8_t*>(pieces.data() + pieceIndex * 20);

    uint8_t actual[20];
    sha1_wincrypt(buffer.data(), (DWORD)buffer.size(), actual);

    return std::memcmp(expected, actual, 20) == 0;
}

/* PIECE DOWNLOAD */

bool TorrentDownloader::downloadOnePiece(int piece_idx) {

    constexpr int BLOCK = 16 * 1024;

    long long piece_len = torrentFile["info"]["piece length"];
    long long total_size = torrentFile["info"].contains("length")
        ? torrentFile["info"]["length"].get<long long>()
        : [&] {
        long long s = 0;
        for (auto& f : torrentFile["info"]["files"])
            s += f["length"].get<long long>();
        return s;
        }();

    long long total_pieces =
        torrentFile["info"]["pieces"].get<std::string>().size() / 20;

    if (piece_idx == total_pieces - 1)
        piece_len = total_size - piece_len * (total_pieces - 1);

    std::vector<uint8_t> piece_buffer(piece_len);

    for (int offset = 0; offset < piece_len; offset += BLOCK) {

        uint32_t req_len =
            (piece_len - offset < BLOCK)
            ? (uint32_t)(piece_len - offset)
            : BLOCK;

        // REQUEST message
        uint32_t msg_len = htonl(13);
        uint8_t id = 6;
        uint32_t idx = htonl(piece_idx);
        uint32_t off = htonl(offset);
        uint32_t len = htonl(req_len);

        if (!send_all(&msg_len, 4) ||
            !send_all(&id, 1) ||
            !send_all(&idx, 4) ||
            !send_all(&off, 4) ||
            !send_all(&len, 4))
            return false;

        // Wait for PIECE
        while (true) {

            uint32_t plen;
            if (!recv_all(&plen, 4)) return false;
            plen = ntohl(plen);
            if (plen == 0) continue;

            uint8_t pid;
            if (!recv_all(&pid, 1)) return false;

            if (pid != 7) {
                std::vector<uint8_t> skip(plen - 1);
                recv_all(skip.data(), skip.size());
                continue;
            }

            uint32_t ridx, roff;
            recv_all(&ridx, 4);
            recv_all(&roff, 4);
            ridx = ntohl(ridx);
            roff = ntohl(roff);

            int data_len = plen - 9;
            recv_all(piece_buffer.data() + roff, data_len);

            {
                std::lock_guard<std::mutex> lock(torrentStatus->mtx);
                torrentStatus->downloaded += data_len;
            }
            break;
        }
    }

    if (!verifyPieceHash(piece_idx, piece_buffer, torrentFile))
        return false;

    DiskManager.WritePiece(
        piece_idx,
        reinterpret_cast<const char*>(piece_buffer.data()),
        piece_buffer.size()
    );

    return true;
}


TorrentDownloader::TorrentDownloader(
    const std::string& path,
    json torrent,
    DiskWriter& DiskWriterManager,
    std::shared_ptr<TorrentStatus> TorrentStatus
)
    : output_path(path),
    torrentFile(torrent),
    DiskManager(DiskWriterManager),
    torrentStatus(TorrentStatus) {
}


void TorrentDownloader::setClientSocket(SOCKET& sock) {
    clientSocket = sock;
}

std::vector<bool> TorrentDownloader::getBitField() {
    return peerBitfield;
}
