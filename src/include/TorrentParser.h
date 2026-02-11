#pragma once
#include <iostream>
#include <json.hpp>

class TorrentParser {

private:
	std::string data;
	size_t pos = 0;
	nlohmann::json parseBInt();
	nlohmann::json parseBString();
	nlohmann::json parseBList();
	nlohmann::json parseBDict();

public:

	TorrentParser();
	void setData(const std::string& input);
	nlohmann::json Parse();
	std::vector<uint8_t> BencodeJson(const nlohmann::json& j);
	static std::string url_encode_bytes(unsigned char* url);

};
