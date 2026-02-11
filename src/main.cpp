#include <iostream>
#include <string>
#include <btcli.h>
#include <filesystem>
#include <TorrentManager.h>
#include<json.hpp>
#include <set>
#include <mutex>

void clearScreen() {
    #ifdef _WIN32
        system("cls"); 
    #else
        system("clear"); 
    #endif
}

#pragma comment(lib, "advapi32.lib")

std::string getPeerWireHome() {
    char* buffer = nullptr;
    size_t len = 0;

    errno_t err = _dupenv_s(&buffer, &len, "PEERWIRE_HOME");
    if (err || !buffer) {
        throw std::runtime_error("PEERWIRE_HOME environment variable not set");
    }

    std::string path(buffer);
    free(buffer); 

    return path;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        exit(1);
    }

    std::string base = getPeerWireHome();
    std::string torrentDir = base + "\\torrents";
    std::string downloadDir = base + "\\downloads";

    std::filesystem::create_directories(torrentDir);
    std::filesystem::create_directories(downloadDir);

	TorrentManager manager(torrentDir, downloadDir);

    std::thread([&manager]() {
        while (true) {
            {
                std::lock_guard<std::mutex> lock(manager.mtx);

                for (auto it = manager.jobs.begin(); it != manager.jobs.end(); ) {
                    if (it->second->completed) {
                        it = manager.jobs.erase(it);
                    }
                    else {
                        ++it;
                    }
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        }).detach();


    httplib::Server server;



    server.set_default_headers(
        {
            { "Access-Control-Allow-Origin", "*" },
            { "Access-Control-Allow-Methods", "GET, POST, OPTIONS" },
            { "Access-Control-Allow-Headers", "Content-Type" }
        }
    );


    server.Options(R"(.*)", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
       }
    );



    server.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("PeerWire backend alive", "text/plain");
        }
    );



    server.Post("/start", [&](const httplib::Request& req, httplib::Response& res) {

        nlohmann::json body;

        try {
            body = nlohmann::json::parse(req.body);
        }

        catch (...) {
            res.status = 400;
            res.set_content("Invalid JSON", "text/plain");
            return;
        }

        std::string jobId = body["jobId"];
        std::string torrentName = body["torrentName"];

        std::string torrentPath = torrentDir + "\\" + torrentName;
        std::cout << "Received request to start torrent: " << torrentPath << "\n";

        if (!std::filesystem::exists(torrentPath)) {
            res.status = 404;
            res.set_content("Torrent file not found", "text/plain");
            return;
        }

		manager.startTorrent(torrentName, jobId);

		res.set_content("Torrent started: " + torrentName, "text/plain");
    });



    server.Get("/status-stream", [&](const httplib::Request& req, httplib::Response& res) {

        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("Connection", "keep-alive");

        // Important: disable content-length
        res.set_chunked_content_provider(
            "text/event-stream",
            [&](size_t /*offset*/, httplib::DataSink& sink) {

                while (true) {
                    nlohmann::json payload = nlohmann::json::array();

                    {
                        std::lock_guard<std::mutex> lock(manager.mtx);
                        for (auto& [id, status] : manager.jobs) {
                            nlohmann::json j;
                            j["jobId"] = id;
                            j["name"] = status->name;
                            j["downloaded"] = status->downloaded;
                            j["total"] = status->total;
                            j["activePeers"] = status->activePeers;
                            j["completed"] = status->completed;
                            j["speed"] = status->speed;
							j["foundPeers"] = status->havePeers;
                            j["log"] = status->log;
                            payload.push_back(j);
                        }
                    }

                    std::string msg = "data: " + payload.dump() + "\n\n";
                    if (!sink.write(msg.data(), msg.size())) {
                        break; // client disconnected
                    }

                    std::this_thread::sleep_for(std::chrono::milliseconds(500));
                }

                return true;
            }
        );
        });

    /*LOGS************************************************************/

    
    std::cout << "Server listening on http://127.0.0.1:8080\n";

    /*LOGS************************************************************/

    server.listen("127.0.0.1", 8080);


   
    WSACleanup();
    return 0;
}
