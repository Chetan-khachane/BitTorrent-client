

#include <TorrentDownloader.h>
#include <bencrypt.h>
#include <TorrentParser.h>
#include <DiskWriter.h>
#include <btcli.h>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <queue>
#include <ctime>
#include <thread>
#include <TorrentManager.h>
#include<btime.h>

#define PEER_ID "-qB4600-123456789012"


#define MAX_PEERS 40


static std::unordered_map<std::string, int> peerFailures;//tracking peers which are failed
nlohmann::json response;


httplib::Result GetPeers(
    const std::string& host,
    int port,
    unsigned char info_hash[],
    const std::string& path,
    long long length,
    const std::string& scheme
) {

    if (host.empty() || path.empty() || length < 0) {
        throw std::invalid_argument("Invalid tracker parameters");
    }

    std::string encoded_info_hash =
        TorrentParser::url_encode_bytes(info_hash);//url encoded info hash for getting peers

    std::string query =
        path +
        "?info_hash=" + encoded_info_hash +
        "&peer_id=" + PEER_ID +
        "&port=6881"
        "&uploaded=0"
        "&downloaded=0"
        "&left=" + std::to_string(length) +
        "&event=started"
        "&compact=1";

    httplib::Result res;

    //only http and https supported
    if (scheme == "https") {
        httplib::SSLClient cli(host, port);
        cli.enable_server_certificate_verification(true);
        res = cli.Get(query.c_str());
    }
    else if (scheme == "http") {
        httplib::Client cli(host, port);
        res = cli.Get(query.c_str());
    }
    else {
        throw std::invalid_argument("Unsupported scheme");
    }


    return res;
}



Tracker::Tracker(const std::vector<std::vector<std::string>>& announceList, unsigned char info_hash_calc[], long long fileLength) {
    //inserting announce url as per tier ordering
    for (auto i : announceList)
        announce_list.insert(announce_list.end(), i.begin(), i.end());

    for (unsigned char i = 0; i < 20; i++)
        info_hash[i] = info_hash_calc[i];

    file_length = fileLength;


    /*LOGS************************************************************/


    for (auto& i : announce_list)
        std::cout << "Tracker LOG :: announce_url_found = " << i << "\n";

    std::cout << "Tracker LOG :: Total File size (in bytes) =  " << file_length << "\n";

    /*LOGS************************************************************/

}


std::vector<std::string> Tracker::GetPeersList() {
    return peers_fetched;
}


std::string Tracker::GetNextAnnounce() {
    if (announce_pos >= announce_list.size()) {
        announce_pos = 0;

        /*LOGS************************************************************/

        std::cout << "Whole announce list exhausted. Restarting from beginning.\n";

        /*LOGS************************************************************/

    }

    return announce_list[announce_pos++];
}

std::string Tracker::GetCurrentAnnounce() {
    if (announce_pos == 0 && !announce_list.empty()) {
        return announce_list[0];
    }
    else if (announce_pos > 0 && announce_pos <= announce_list.size()) {
        return announce_list[announce_pos - 1];
    }
    return "";
}

std::vector<std::string> Tracker::GetAnnounceList() {
    return announce_list;
}

bool isIPv6(const std::string& address) {
    return std::count(address.begin(), address.end(), ':') > 1;
}


void Tracker::fetchPeers() {


    if (announce_list.empty()) {
        std::cerr << "Announce list empty\n";
        return;
    }

    std::unordered_set<std::string> unique_peers;

    /*LOGS************************************************************/


    std::cout << "Fetching peers from tracker...\n";

    /*LOGS************************************************************/


    while (announce_pos < announce_list.size()) {
        std::string tracker_url = GetNextAnnounce();

        /*LOGS************************************************************/

        std::cout << "\nTracker fetchpeers log :: tracker_url selected = " << tracker_url << "\n";


        /*LOGS************************************************************/



        size_t scheme_pos = tracker_url.find("://");
        if (scheme_pos == std::string::npos)
            continue;

        std::string scheme = tracker_url.substr(0, scheme_pos);



        if (scheme != "http" && scheme != "https")
            continue;

        std::string rest = tracker_url.substr(scheme_pos + 3);
        size_t slash_pos = rest.find('/');
        std::string hostport = rest.substr(0, slash_pos);
        std::string path = (slash_pos == std::string::npos) ? "/" : rest.substr(slash_pos);

        std::string host = hostport;
        int port = (scheme == "https") ? 443 : 80;

        size_t colon = hostport.find(':');
        if (colon != std::string::npos) {
            host = hostport.substr(0, colon);
            port = std::stoi(hostport.substr(colon + 1));
        }

        httplib::Result res;


        try {


            /*LOGS************************************************************/

            std::cout << "Tracker fetchpeers log :: host selected = " << host << "\n";
            std::cout << "Tracker fetchpeers log :: port selected = " << port << "\n";
		    std::cout << "Info hash selected = ";    
            for (auto& i : info_hash) {
                printf("%02x", i);
            }
            std::cout << "\nTracker fetchpeers log :: path selected = " << path << "\n";
            std::cout << "Tracker fetchpeers log :: file_length selected = " << file_length << "\n";
            std::cout << "Tracker fetchpeers log :: scheme selected = " << scheme << "\n";

            /*LOGS************************************************************/



            res = GetPeers(host, port, info_hash, path, file_length, scheme);
        }
        catch (...) {
            continue;
        }

        /*LOGS************************************************************/
		std::cout << "Tracker fetchpeers log :: response received from tracker :: \n";
        std::cout << res->status << '\n';

        /*LOGS************************************************************/


        if (!res || res->status != 200) {

            continue;
        }


        TorrentParser parser;
        parser.setData(res->body);
        json decoded = parser.Parse();

        if (!decoded.contains("peers")) {
            /*LOGS************************************************************/

            std::cout << "Tracker fetchpeers log :: res not contain peers dict so continuing... "<< "\n";

            /*LOGS************************************************************/

            continue;
        }

        auto& peers_val = decoded["peers"];

        // compact peer format
        if (peers_val.is_string()) {

            const std::string& peers = peers_val.get<std::string>();
            for (size_t i = 0; i + 6 <= peers.size(); i += 6) {

                const unsigned char* p =
                    reinterpret_cast<const unsigned char*>(peers.data() + i);

                uint16_t peer_port = (p[4] << 8) | p[5];
                std::string ip =
                    std::to_string(p[0]) + "." +
                    std::to_string(p[1]) + "." +
                    std::to_string(p[2]) + "." +
                    std::to_string(p[3]);

                unique_peers.insert(ip + ":" + std::to_string(peer_port));
            }
            break;
        }
        // non-compact format
        else if (peers_val.is_array()) {
            for (auto& peer : peers_val) {
                std::string ip = peer["ip"];
                int peer_port = peer["port"];
                if (ip == "10.111.84.122") continue;
                unique_peers.insert(ip + ":" + std::to_string(peer_port));
            }
            break;
        }
    }


    peers_fetched.assign(unique_peers.begin(), unique_peers.end());




    /*LOGS************************************************************/


    std::cout << "Tracker fetchpeers log :: peers_fetched :- " << "\n\n";


    for (auto& i : peers_fetched) {
        std::cout << "Tracker fetchpeers log :: peer  = " << i << "\n";
    }


    /*LOGS************************************************************/



    for (auto& peer : peers_fetched) {

        if (deadPeers.contains(peer)) continue;

        if (activePeers.contains(peer)) continue;



        peerQueue.push(peer);

    }



    /*LOGS************************************************************/

    std::cout << "Total Peers fetched  =  " << peers_fetched.size() << "\n\n";

    /*LOGS************************************************************/

}



int Tracker::getAnnouncePos() {
    return announce_pos;
}


PieceManager::PieceManager(size_t totalPieces, const unsigned char* iHash) {

    /*LOGS************************************************************/

    std::cout << "PieceManager  LOG :: totalPieces required to download =  " << totalPieces<<"\n\n";

    /*LOGS************************************************************/

    pieceState.assign(totalPieces, PieceState::MISSING);//setting up PieceManager with all pieces as missing initially




    std::memcpy(info_hash, iHash, 20);


}


bool PieceManager::allComplete() {
    for (auto status : pieceState) {
        if (status != PieceState::COMPLETE)
            return false;
    }
    return true;
}

const unsigned char* PieceManager::getInfoHash() {
    return info_hash;
}

void PieceManager::markPieceAsMissing(size_t index) {
    if (index < pieceState.size())
        pieceState[index] = PieceState::MISSING;
}

void PieceManager::markPieceAsDownloading(size_t index) {
    if (index < pieceState.size()) {
        pieceState[index] = PieceState::DOWNLOADING;
    }
}

void PieceManager::markPieceAsCompleted(size_t index) {
    if (index < pieceState.size())
        pieceState[index] = PieceState::COMPLETE;
}


int PieceManager::selectPiece(const std::vector<bool>& peerBitfield) {
    std::vector<int> candidates;

    for (int i = 0; i < pieceState.size(); i++) {
        if (pieceState[i] == PieceState::MISSING && peerBitfield[i]) {
            candidates.push_back(i);
        }
    }

    if (candidates.empty())
        return -1;

    int idx = candidates[rand() % candidates.size()];
    pieceState[idx] = PieceState::DOWNLOADING;
    return idx;
}



void PieceManager::workerThreadFunc(
    const std::string& peer,
    Tracker& tracker,
    const std::string& output_path,
    DiskWriter& DiskWriterManager,
    const json& torrent_data,
    std::shared_ptr<TorrentStatus> TorrentStatus
) {

    size_t colon_pos = peer.find(":");
    std::string ip = peer.substr(0, colon_pos);
    size_t port = std::stoul(peer.substr(colon_pos + 1));

    SOCKET sock = INVALID_SOCKET;


    /*LOGS************************************************************/


    std::cout << "Thread :: ip = " << ip << " port = " << port << "\n";

    /*LOGS************************************************************/


    for (int i = 0; i < 3; i++) {

        response["message"] = getLocalTimestamp() + "Attempting handshake with  (try " + std::to_string(i + 1) + ")\n";
        response["code"] = 0;
        TorrentStatus->log = response;
        sock = make_handshake(ip, port, getInfoHash());

        /*LOGS************************************************************/

        std::cout << "Thread :: sock = " << sock << "\n";


        /*LOGS************************************************************/

        if (sock != INVALID_SOCKET) {

            /*LOGS************************************************************/

            std::cout << "Thread :: socket is established,success for "<<ip<<":"<<port << "\n";

            /*LOGS************************************************************/

            response["message"] = getLocalTimestamp() + "Handshake successful  \n";
            response["code"] = 1;
            TorrentStatus->log = response;

            break;
        }

        /*LOGS************************************************************/

        std::cout << "Socket failed retrying :: for "<<ip<<":"<<port<<"(" << i + 1 << "\n";

        /*LOGS************************************************************/

        response["message"] = getLocalTimestamp() + "Handshake failed with  (try " + std::to_string(i + 1) + ")\n";
        response["code"] = 0;
        TorrentStatus->log = response;

        std::this_thread::sleep_for(
            std::chrono::milliseconds(200 * (i + 1))
        );
    }

    if (sock == INVALID_SOCKET) {
        std::lock_guard<std::mutex> lock(tracker.peerMutex);
        tracker.activePeers.erase(peer);
        TorrentStatus->activePeers = tracker.activePeers.size();
        tracker.deadPeers.insert(peer);
        response["message"] = getLocalTimestamp() + "Handshake failed with  after 3 attempts. Marking peer as dead.\n";
        response["code"] = 0;
        TorrentStatus->log = response;
        return;
    }

    /*LOGS************************************************************/

    std::cout << "Handshake successful :: \n";

    /*LOGS************************************************************/

    response["message"] = getLocalTimestamp() + "Handshake successful  \n";
    response["code"] = 0;
    TorrentStatus->log = response;

    //assigning downloader to peer
    TorrentDownloader downloader(output_path, torrent_data, DiskWriterManager, TorrentStatus);

    response["message"] = getLocalTimestamp() + "Attached downloader to peer \n";
    response["code"] = 0;
    TorrentStatus->log = response;
    /*LOGS************************************************************/

    std::cout << "Attached downloader for :: " << ip << ":" << port << std::endl;

    /*LOGS************************************************************/

    downloader.setClientSocket(sock);



    response["message"] = getLocalTimestamp() + "Waiting for unchoke from peer \n";
    response["code"] = 0;
    TorrentStatus->log = response;

    if (!downloader.waitForUnchoke()) {

        closesocket(sock);
        std::lock_guard<std::mutex> lock(tracker.peerMutex);
        tracker.activePeers.erase(peer);
        TorrentStatus->activePeers = tracker.activePeers.size();
        tracker.deadPeers.insert(peer);

        /*LOGS************************************************************/

        std::cout << peer << " : " << " got choked\n";

        /*LOGS************************************************************/
        response["message"] = getLocalTimestamp() + "receuvied choked. Marking peer as dead.\n";
        response["code"] = 0;
        TorrentStatus->log = response;

        return;
    }

    /*LOGS************************************************************/

    std::cout << "Unchoke  successful :: for :: \n" << ip << ":" << port << "\n";

    /*LOGS************************************************************/
    response["message"] = getLocalTimestamp() + "Peer unchoked client. Starting piece download.\n";
    response["code"] = 0;
    TorrentStatus->log = response;

    while (!allComplete()) {

        int index = selectPiece(downloader.getBitField());

        /*LOGS************************************************************/

        std::cout << "selected piece idx = " << index << " " << ip << ":" << port << "\n";

        /*LOGS************************************************************/
        response["message"] = getLocalTimestamp() + "Selected piece index " + std::to_string(index) + " for download\n";
        response["code"] = 0;
        TorrentStatus->log = response;

        if (index == -1)
            break;
        if (!downloader.downloadOnePiece(index)) {

            {
                std::lock_guard<std::mutex> lock(tracker.peerMutex);
                markPieceAsMissing(index);
                response["message"] = getLocalTimestamp() + "Failed to download piece index " + std::to_string(index) + " from peer\n";
                response["code"] = 0;
                TorrentStatus->log = response;
                peerFailures[peer]++;
            }

            if (peerFailures[peer] >= 3) {

                std::lock_guard<std::mutex> lock(tracker.peerMutex);
                tracker.activePeers.erase(peer);
                TorrentStatus->activePeers = tracker.activePeers.size();
                tracker.deadPeers.insert(peer);
                closesocket(sock);
                response["message"] = getLocalTimestamp() + "Peer failed to deliver pieces 3 times. Marking peer as dead.\n";
                response["code"] = 0;
                TorrentStatus->log = response;
                return;
            }

            response["message"] = getLocalTimestamp() + "Failed to download piece index " + std::to_string(index) + " from peer\n";
            response["code"] = 0;
            TorrentStatus->log = response;
            /*LOGS************************************************************/
            continue;
        }

        std::lock_guard<std::mutex> lock(tracker.peerMutex);
        markPieceAsCompleted(index);

        response["message"] = getLocalTimestamp() + "Successfully downloaded piece index " + std::to_string(index) + "\n";
        response["code"] = 0;
        TorrentStatus->log = response;
        /*LOGS************************************************************/
        std::cout << std::endl;
        std::cout << "Piece " << index << " is completed\n\n";

        /*LOGS************************************************************/

    }


    closesocket(sock);

    response["message"] = getLocalTimestamp() + "Completed downloading pieces from peer. Closing connection.\n";
    response["code"] = 0;
    TorrentStatus->log = response;

    /*LOGS************************************************************/

    std::cout << "peer " << peer << " successfully closed socket\n\n";

    /*LOGS************************************************************/

    {
        std::lock_guard<std::mutex> lock(tracker.peerMutex);
        tracker.activePeers.erase(peer);
        TorrentStatus->activePeers = tracker.activePeers.size();
        response["message"] = getLocalTimestamp() + "Finished all piece downloads from peer. Marking peer as inactive.\n";
        response["code"] = 0;
        TorrentStatus->log = response;
    }
}






SOCKET make_handshake(
    const std::string& peerIP,
    const size_t& peerPort,
    const unsigned char* info_hash
) {
	uint8_t msg[68] = { 0 };//68byte handshake message as per bittorrent protocol specification
    msg[0] = 19;
    memcpy(msg + 1, "BitTorrent protocol", 19);
    memcpy(msg + 28, info_hash, 20);
    memcpy(msg + 48, PEER_ID, 20);

	SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);//using AF_INET for IPV4 as most of the peers are IPV4 and also for simplicity. SOCK_STREAM for TCP connection and IPPROTO_TCP for TCP protocol
    if (s == INVALID_SOCKET) return INVALID_SOCKET;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
	addr.sin_port = htons((u_short)peerPort);//Big endian port number
	inet_pton(AF_INET, peerIP.c_str(), &addr.sin_addr);//converting IP address from string to binary form

	if (connect(s, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {//attempting connection to peer
        closesocket(s);
        return INVALID_SOCKET;
    }

	if (send(s, (char*)msg, 68, 0) != 68) {//sending handshake message to peer
        closesocket(s);
        return INVALID_SOCKET;
    }

    uint8_t resp[68];
	if (recv(s, (char*)resp, 68, MSG_WAITALL) != 68) {//receiving handshake response from peer
        closesocket(s);
        return INVALID_SOCKET;
    }

	if (memcmp(resp + 28, info_hash, 20) != 0) {//validating info hash in handshake response
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}




void TorrentCLI(std::string output_path,
    std::string TorrentFilePath,
    std::string TorrentFileName,
    std::shared_ptr<TorrentStatus> Status) {

    std::vector<std::thread> peerThreads;
    std::string file_name = TorrentFileName;
    std::ifstream file;
    std::string info;
    TorrentParser parser;
    json torrent_data;
    std::vector<uint8_t> encoded_info;
    std::vector<std::string> peers_fetched;
    unsigned char info_hash[20];
    std::vector<std::vector<std::string>> announce_list;
    std::filesystem::path torrentPath;


    /*LOGS************************************************************/

    std::cout << "nputted files  :: \n\n";
    std::cout << "output_path : " << output_path << std::endl;
    std::cout << "file_path : " << TorrentFilePath << std::endl;
    std::cout << "file_name : " << file_name << std::endl << std::endl;

    /*LOGS************************************************************/

    response["message"] = getLocalTimestamp() + " : TorrentCLI started with file " + file_name + "\n";
    response["code"] = 0;

    Status->log = response;

    //Reading Torrent File
    if (!TorrentFilePath.empty() && !TorrentFileName.empty()) {
        torrentPath = std::filesystem::path(TorrentFilePath) / TorrentFileName;
    }
    else {
        std::cerr << "Error: Torrent file path or name not provided\n";
        response["message"] = getLocalTimestamp() + " : Error: Torrent file path or name not provided\n";
        response["code"] = 1;
        Status->log = response;
        return;
    }

    file.open(torrentPath, std::ios::binary); // opening file stream of torrrent file

    if (!file) {
        std::cerr << "Error opening file: " << file_name << std::endl;
        response["message"] = getLocalTimestamp() + " : Error opening file: " + file_name + "\n";
        response["code"] = 1;
        Status->log = response;
        return;
    }

    std::filesystem::path p{ torrentPath };//path creation base
    info.assign(std::filesystem::file_size(p), '_');//buffer creation
    file.read(info.data(), std::filesystem::file_size(p));

    //parsing torrent file
    parser.setData(info);
    torrent_data = parser.Parse();

    //bencoding for info hash calculation
    encoded_info = parser.BencodeJson(torrent_data["info"]);

    /*LOGS************************************************************/

    if (torrent_data.contains("announce-list")) {

        announce_list = torrent_data["announce-list"]
            .get<std::vector<std::vector<std::string>>>();
    }
    else {
        std::string tracker = torrent_data["announce"].get<std::string>();
        announce_list.push_back({ tracker });
    }



    for (auto& i : announce_list) {
        for (auto& j : i)
            std::cout << "announce list :: " << j << "\n";
    }

    /*LOGS************************************************************/


    sha1_wincrypt(
        encoded_info.data(),
        (DWORD)encoded_info.size(),
        info_hash
    );//info hash generation

    response["message"] = getLocalTimestamp() + " : Torrent file parsed successfully. Info hash calculated.\n";
    response["code"] = 0;
    Status->log = response;


    //calculate total file length
    long long file_length = 0;

    if (torrent_data["info"].contains("length"))
        file_length = torrent_data["info"]["length"].get<long long>();
    else
    {
        std::vector<json> files = torrent_data["info"]["files"];
        for (json file : files)
        {
            file_length += file["length"].get<long long>();
        }
    }



    response["message"] = getLocalTimestamp() + " : Total file length calculated: " + std::to_string(file_length) + " bytes\n";
    response["code"] = 0;
    Status->log = response;


    Tracker tracker(announce_list, info_hash, file_length);//registering tracker as torrent file extracted announce urls


    response["message"] = getLocalTimestamp() + " : Tracker initialized with announce URLs and file length.\n";
    response["code"] = 0;
    Status->log = response;




    tracker.fetchPeers();//fetching peers for round 1

    response["message"] = getLocalTimestamp() + " : Initial peer fetch completed. Peers fetched: " + std::to_string(tracker.GetPeersList().size()) + "\n";
    response["code"] = 0;
    Status->log = response;


    //pieceManager Setting
    PieceManager pieceManager(
        (torrent_data["info"]["pieces"].get<std::string>().size()) / 20
        , info_hash);

    response["message"] = getLocalTimestamp() + " : PieceManager initialized with total pieces and info hash.\n";
    response["code"] = 0;
    Status->log = response;
    //DiskWriter Setting
    DiskWriter DiskWriterManager(torrent_data, output_path);

    response["message"] = getLocalTimestamp() + " : DiskWriter initialized with torrent data and output path.\n";
    response["code"] = 0;
    Status->log = response;

    response["message"] = getLocalTimestamp() + " : Initialization complete. Starting download loop.\n";
    response["code"] = 0;
    Status->log = response;

    //setting file totol for frontend
    Status->total = file_length;

    //assigning jobs to each peer until all pieces completed
    while (!pieceManager.allComplete()) {

        std::lock_guard<std::mutex> lock(tracker.peerMutex);
        //filling till MAX_PEERS or peerQueue goes empty
        while (tracker.activePeers.size() < MAX_PEERS && !tracker.peerQueue.empty()) {

            std::string peer;

            peer = tracker.peerQueue.front();
            tracker.peerQueue.pop();

            if (isIPv6(peer)) continue;

            tracker.activePeers.insert(peer);

            peerThreads.emplace_back(
                &PieceManager::workerThreadFunc,
                &pieceManager,
                peer,
                std::ref(tracker),
                output_path,
                std::ref(DiskWriterManager),
                torrent_data,
                Status
            );

            response["message"] = getLocalTimestamp() + " : Assigned peer " + " to a worker thread.\n";
            response["code"] = 0;
            Status->log = response;

            Status->activePeers = tracker.activePeers.size();
        }


        //calcuating downloading speed upon amount of downloaded bytes so far
        auto now = std::chrono::steady_clock::now();
        double seconds =
            std::chrono::duration<double>(now - Status->lastTick).count();

        if (seconds >= 1.0) {
            long long current = Status->downloaded;

            double speed =
                (current - Status->lastDownloaded) / seconds;

            {
                std::lock_guard<std::mutex> lock(Status->mtx);
                Status->speed = speed;
            }

            Status->lastDownloaded = current;
            Status->lastTick = now;
        }


       

        // fetching new peers from tracker 
        if (tracker.activePeers.empty() && !pieceManager.allComplete() && tracker.getAnnouncePos() < tracker.GetAnnounceList().size()) {

            tracker.fetchPeers();


            response["message"] = getLocalTimestamp() + " : Active peers exhausted. Fetching new peers from tracker.\n";
            response["code"] = 0;
            Status->log = response;



        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }




    /*LOGS************************************************************/


    std::cout << "Waiting for peer threads to finish...\n";

    /*LOGS************************************************************/

    response["message"] = getLocalTimestamp() + " : Download loop complete. Waiting for peer threads to finish.\n";
    response["code"] = 0;
    Status->log = response;

    for (auto& t : peerThreads) {
        if (t.joinable()) {
            t.join();
        }
    }


    /*LOGS************************************************************/

    std::cout << "TorrentCLI finished safely\n";

    /*LOGS************************************************************/

    response["message"] = getLocalTimestamp() + " : All peer threads finished. TorrentCLI exiting safely.\n";
    response["code"] = 0;
    Status->log = response;



}