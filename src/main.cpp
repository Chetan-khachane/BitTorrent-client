#define WIN32_LEAN_AND_MEAN  

#include <winsock2.h>        
#include <windows.h>
#include <wincrypt.h>

#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include <variant>
#include <unordered_map>

#include "lib/nlohmann/json.hpp"
#include <httplib.h>

#pragma comment(lib, "advapi32.lib")

bool sha1_wincrypt(
    const unsigned char* data,
    DWORD dataLen,
    unsigned char out[20]
) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    DWORD hashLen = 20;

    if (!CryptAcquireContext(&hProv, NULL, NULL,
        PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    if (!CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash))
        return false;

    if (!CryptHashData(hHash, data, dataLen, 0))
        return false;

    if (!CryptGetHashParam(hHash, HP_HASHVAL, out, &hashLen, 0))
        return false;

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return true;
}

using json = nlohmann::json;


//Bencode Parser Design

struct BencodeValue;

using BencodeInt = long long;
using BencodeStr = std::string;
using BencodeList = std::vector<BencodeValue>;
using BencodeDict = std::unordered_map<std::string, BencodeValue>;

struct BencodeValue {
    std::variant<BencodeInt, BencodeStr, BencodeList, BencodeDict> value;
};

class TorrentParser {
private:
    const std::string& data;
    size_t pos = 0;

    // ---- Integer ----
    json parseBInt() {
        pos++; // skip 'i'

        size_t start = pos;
        while (pos < data.size() && data[pos] != 'e')
            pos++;

        if (pos >= data.size())
            throw std::runtime_error("Unterminated integer");

        long long val = std::stoll(data.substr(start, pos - start));
        pos++; // consume 'e'
        return json(val);
    }

    // ---- String ----
    json parseBString() {
        if (pos >= data.size() || !std::isdigit(data[pos])) {
            throw std::runtime_error("String does not start with digit");
        }

        size_t colon = data.find(':', pos);
        if (colon == std::string::npos)
            throw std::runtime_error("Missing ':' in string");

        // validate length field is digits only
        for (size_t i = pos; i < colon; ++i) {
            if (!std::isdigit(data[i]))
                throw std::runtime_error("Invalid string length field");
        }

        size_t len = std::stoull(data.substr(pos, colon - pos));
        pos = colon + 1;

        if (pos + len > data.size())
            throw std::runtime_error("String exceeds buffer");

        std::string str = data.substr(pos, len);
        pos += len;
        return json(str);
    }

    // ---- List ----
    json parseBList() {
        pos++; // skip 'l'
        json list = json::array();

        while (pos < data.size() && data[pos] != 'e') {
            list.push_back(Parse());
        }

        if (pos >= data.size())
            throw std::runtime_error("Unterminated list");

        pos++; // consume 'e'
        return list;
    }

    // ---- Dictionary ----
    json parseBDict() {
        pos++; // skip 'd'
        json dict = json::object();

        while (pos < data.size() && data[pos] != 'e') {
            if (!std::isdigit(data[pos]))
                throw std::runtime_error("Dictionary key must be string");
            json key = parseBString();
            json value = Parse();
            dict[key.get<std::string>()] = value;
        }

        if (pos >= data.size())
            throw std::runtime_error("Unterminated dictionary");

        pos++; // consume 'e'
        return dict;
    }

public:
    TorrentParser(const std::string& input)
        : data(input), pos(0) {
        if (data.empty())
            throw std::runtime_error("Empty input");
    }

    json Parse() {
        if (pos >= data.size())
            throw std::runtime_error("Unexpected end of data");

        char c = data[pos];

        if (c == 'i') return parseBInt();
        if (c == 'l') return parseBList();
        if (c == 'd') return parseBDict();
        if (std::isdigit(c)) return parseBString();



        throw std::runtime_error(std::string("Invalid bencode char: ") + c);
    }

    std::vector<uint8_t> BencodeJson(const json& j) {
        std::vector<uint8_t> out;

        if (j.is_object()) {
            out.push_back('d');

            std::vector<std::string> keys;
            for (auto& [k, _] : j.items())
                keys.push_back(k);

            std::sort(keys.begin(), keys.end());

            for (const auto& k : keys) {
                // key
                auto len = std::to_string(k.size());
                out.insert(out.end(), len.begin(), len.end());
                out.push_back(':');
                out.insert(out.end(), k.begin(), k.end());

                // value
                auto encoded_value = BencodeJson(j.at(k));
                out.insert(out.end(),
                    encoded_value.begin(),
                    encoded_value.end());
            }

            out.push_back('e');
        }
        else if (j.is_array()) {
            out.push_back('l');
            for (const auto& v : j) {
                auto encoded_item = BencodeJson(v);
                out.insert(out.end(),
                    encoded_item.begin(),
                    encoded_item.end());
            }
            out.push_back('e');
        }
        else if (j.is_number_integer()) {
            out.push_back('i');
            auto num = std::to_string(j.get<long long>());
            out.insert(out.end(), num.begin(), num.end());
            out.push_back('e');
        }
        else if (j.is_string()) {
            const auto& s = j.get<std::string>();
            auto len = std::to_string(s.size());
            out.insert(out.end(), len.begin(), len.end());
            out.push_back(':');
            out.insert(out.end(), s.begin(), s.end());
        }
        else if (j.is_binary()) {
            const auto& b = (j.get_binary());
            auto len = std::to_string(b.size());
            out.insert(out.end(), len.begin(), len.end());
            out.push_back(':');
            out.insert(out.end(), b.begin(), b.end());
        }
        else {
            throw std::runtime_error("Invalid JSON type for bencode");
        }

        return out;
    }

};

std::string url_encode_bytes(unsigned char* url) {
    std::string encoded_url;
	static const char hex_chars[] = "0123456789ABCDEF";

    for (int i = 0; i < 20; i++) {
		unsigned char c = url[i];
        encoded_url.push_back('%');
        encoded_url.push_back(hex_chars[c >> 4]);
        encoded_url.push_back(hex_chars[c & 0x0F]);
    }
	return encoded_url;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }

    std::string command = argv[1];

    if (command == "decode") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
            return 1;
        }
        // You can use print statements as follows for debugging, they'll be visible when running tests.
        std::cerr << "Logs from your program will appear here!" << std::endl;
        try {
           
			const std::string& s = argv[2];
            TorrentParser parser(s);
            json result = parser.Parse();

            std::cout << result.dump(2) << std::endl;
        }
        catch (const std::exception& e) {
            std::cerr << "Parser error: " << e.what() << std::endl;
            return 3;
        }
    } 
    else if (command == "info") {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " parse <bencoded .torrent file>" << std::endl;
            return 1;
        }
        std::string file_name = argv[2];
        std::ifstream file(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file: " << file_name << std::endl;
            return 1;
        }
        std::filesystem::path p{ argv[2] };//path creation base
        std::string info(std::filesystem::file_size(p), '_');//buffer creation
        file.read(info.data(), std::filesystem::file_size(p));//read file data into buffer
        //info holds .torrent file content

        TorrentParser parser(info);
        json torrent_data = parser.Parse();
		//json info_dict = torrent_data["info"];
        auto encoded_info = parser.BencodeJson(torrent_data["info"]);
        unsigned char info_hash[20];

        sha1_wincrypt(
            encoded_info.data(),
            (DWORD)encoded_info.size(),
            info_hash
        );
        
        std::cout << "Tracker URL : " << torrent_data["announce"] << "\nLength : "<<torrent_data["info"]["length"] << "\n";
        std::cout << "Info Hash: ";
        for (int i = 0; i < 20; i++) {
            printf("%02x", info_hash[i]);
        }
		std::cout << std::endl;
        std::cout << "Piece Length : " << torrent_data["info"]["piece length"] << "\n";
		std::cout << "Piece Hashes : \n";
       
        std::string pieces_str = torrent_data["info"]["pieces"].get<std::string>();


        if (pieces_str.empty()) {
            printf("ERROR: pieces is empty\n");
            return 1;
        }

        if (pieces_str.size() % 20 != 0) {
            printf("ERROR: invalid pieces size\n");
            return 1;
        }

        size_t idx = 0;
        for (uint8_t b : pieces_str) {
            printf("%02x", b);
            if (++idx % 20 == 0)
                printf("\n");
        }
    }
    else if (command == "peers") {
        std::string file_name = argv[2];
        std::ifstream file(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file: " << file_name << std::endl;
            return 1;
        }
        std::filesystem::path p{ argv[2] };//path creation base
        std::string info(std::filesystem::file_size(p), '_');//buffer creation
        file.read(info.data(), std::filesystem::file_size(p));//read file data into buffer
        //info holds .torrent file content
		TorrentParser parser(info);
		json torrent_data = parser.Parse();
		std::string tracker_url = torrent_data["announce"].get<std::string>();
        //http://127.0.0.1:5173/announce
        //scheme : http:// 
        //hostport : 127.0.0.1:5173
        //port : 5173
        //host: 127.0.0.1
        //path : announce

        auto scheme_pos = tracker_url.find("://");
        auto rest = (scheme_pos == std::string::npos) ? tracker_url :  tracker_url.substr(scheme_pos+3);
        auto slash_pos = rest.find('/');
        auto hostport = rest.substr(0, slash_pos);
        std::string path = (slash_pos == std::string::npos) ? "/" : rest.substr(slash_pos);
        std::string host = hostport;
        int port = 80;
        auto colon = hostport.find(":");
        if (colon != std::string::npos) {
            host = host.substr(0,colon);
            port = std::stoi(host.substr(colon + 1));
        }

        httplib::Client cli(host, port);
        auto encoded_info = parser.BencodeJson(torrent_data["info"]);
        unsigned char info_hash[20];

        sha1_wincrypt(
            encoded_info.data(),
            (DWORD)encoded_info.size(),
            info_hash
        );

        std::string encoded_url = url_encode_bytes(info_hash);

        std::string query =
            path +
            "?info_hash=" + encoded_url +
            "&peer_id=-PC0001-123456789012"
            "&port=6881"
            "&uploaded=0"
            "&downloaded=0"
            "&left=" + std::to_string(torrent_data["info"]["length"].get<int64_t>()) +
            "&compact=1";

        httplib::Headers headers{};
        httplib::Result res = cli.Get(query.c_str());
        if (!res)
        {
            auto err = res.error(); // httplib::Error enum
            std::cerr << "Request failed: " << httplib::to_string(err) << '\n';
            return 1;
        }
 
        std::string const& response_body = res->body;
        TorrentParser BencodeResponseParser(response_body);
        json decoded_response = BencodeResponseParser.Parse();
      
        std::string const& peers_str = decoded_response.at("peers");

        std::vector<uint8_t> peers(
            peers_str.begin(),
            peers_str.end()
        );

        if (peers.empty()) {
            std::cout << "No peers returned by tracker (swarm empty)\n";
            return 0; // or just skip peer parsing
        }
       
        for (size_t i = 0; i < peers.size(); i += 6) {
            uint8_t ip1 = peers[i + 0];
            uint8_t ip2 = peers[i + 1];
            uint8_t ip3 = peers[i + 2];
            uint8_t ip4 = peers[i + 3];

            uint16_t port =
                (static_cast<uint16_t>(peers[i + 4]) << 8) |
                peers[i + 5];

            std::cout
                << (int)ip1 << '.'
                << (int)ip2 << '.'
                << (int)ip3 << '.'
                << (int)ip4
                << ':' << port << '\n';
        }

    }
    else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
