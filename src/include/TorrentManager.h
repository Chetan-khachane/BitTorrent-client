#pragma once
#include<iostream>
#include<thread>
#include<btcli.h>
#include<unordered_map>

struct TorrentStatus {
	std::mutex mtx;
	std::string id;
	std::string name;
	long long downloaded = 0;
	long long total = 0;
	double speed = 0.0;
	int activePeers = 0;
	long long lastDownloaded = 0;
	std::chrono::steady_clock::time_point lastTick;
	bool completed = false;
	bool havePeers = true;
	nlohmann::json log;
};

class TorrentManager {
	private:
	std::string torrentDirectory;
	std::string downloadDirectory;
	
	public : 
		TorrentManager(std::string torrentDir, std::string downloadDir);
		std::mutex mtx;
		std::unordered_map<std::string, std::shared_ptr<TorrentStatus>> jobs;
		std::string startTorrent(std::string TorrentName, std::string JobId);
};