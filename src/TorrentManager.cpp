#include<iostream>
#include<thread>
#include<btcli.h>
#include<unordered_map>
#include <TorrentManager.h>

TorrentManager::TorrentManager(std::string torrentDir,std::string downloadDir) : torrentDirectory(torrentDir),downloadDirectory(downloadDir) {}


std::string  TorrentManager::startTorrent(std::string TorrentName,std::string JobId) {

        auto status = std::make_shared<TorrentStatus>();
        status->id = JobId;
        status->name = TorrentName;
        {
             std::lock_guard<std::mutex> lock(mtx);
			 jobs[JobId] = status;
        }
        std::thread([=]() {


            /*LOGS************************************************************/

            std::cout << "Starting torrent: " << TorrentName << "\n";

            /*LOGS************************************************************/

            TorrentCLI(downloadDirectory, torrentDirectory, TorrentName,jobs[JobId]);

           
                status->completed = true;

                
            /*LOGS************************************************************/

            std::cout << "Finished torrent: " << TorrentName << "\n";

            /*LOGS************************************************************/


            }).detach();

        return JobId;

}
