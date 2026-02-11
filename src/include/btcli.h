#pragma once
#define CPPHTTPLIB_OPENSSL_SUPPORT

#include <httplib.h>
#include<vector>
#include<string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <queue>
#include <DiskWriter.h>
#include <unordered_set>
#include<mutex>
#include<json.hpp>
#pragma comment(lib, "libssl.lib")
#pragma comment(lib, "libcrypto.lib")

struct TorrentStatus;

enum class PieceState {
	MISSING,
	DOWNLOADING,
	COMPLETE
};

SOCKET make_handshake(const std::string& peerIP, const size_t& peerPort, const unsigned char* info_hash);

void TorrentCLI(std::string output_path,
	std::string TorrentFilePath,
	std::string TorrentFileName,
	std::shared_ptr<TorrentStatus> Status);

class Tracker {
private:

	std::vector<std::string> announce_list;
	std::vector<std::string> peers_fetched;
	int announce_pos = 0;
	unsigned char info_hash[20];
	long long file_length;
	
public:

	std::mutex peerMutex;
	std::queue<std::string> peerQueue;
	std::unordered_set<std::string> activePeers;
	std::unordered_set<std::string> deadPeers;
	Tracker(const std::vector<std::vector<std::string>>& announceList, unsigned char info_hash_calc[], long long fileLength);
	std::vector<std::string> GetPeersList();
	std::string GetNextAnnounce();
	std::string GetCurrentAnnounce();
	std::vector<std::string> GetAnnounceList();
	int getAnnouncePos();
	void fetchPeers();

};

class PieceManager {

private:

	std::vector<PieceState> pieceState;
	unsigned char info_hash[20];
	std::mutex pieceMutex;

public:

	void workerThreadFunc(const std::string& peer,
		Tracker& tracker,
		const std::string& output_path,
		DiskWriter& DiskWriterManager,
		const nlohmann::json& torrent_data,
		std::shared_ptr<TorrentStatus> TorrentStatus);
	bool allComplete();
	PieceManager(size_t totalPieces,const unsigned char *iHash);
	void markPieceAsDownloading(size_t index);
	const unsigned char* getInfoHash();
	void markPieceAsCompleted(size_t index);
	void markPieceAsMissing(size_t index);
	int selectPiece(const std::vector<bool>& peerBitfield);

};


httplib::Result GetPeers(
	const std::string& host,
	int port,
	unsigned char info_hash[],
	const std::string& path,
	long long length,
	const std::string& scheme
);