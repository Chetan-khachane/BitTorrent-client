#define WIN32_LEAN_AND_MEAN  
#pragma comment(lib, "Ws2_32.lib")
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
#include <winsock2.h>
#include <ws2tcpip.h>



#include <cstdlib>

void clearScreen() {
    #ifdef _WIN32
        system("cls"); // Command for Windows
    #else
        system("clear"); // Command for Linux/macOS
    #endif
}

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
    std::string data;
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
    TorrentParser()
        {}

    void setData(const std::string &input) {
        data = input;
        pos = 0;
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

std::vector<uint8_t> make_handshake(std::vector<char> message,const std::string& peerIP,const size_t& peerPort,SOCKET* sockfd) {
    std::cout << "Handshake in progress...\n\n";
	std::cout << "Connecting to " << peerIP << ":" << peerPort << std::endl;

    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "WSAStartup failed\n";
        exit(1);
    }

    *sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (*sockfd == INVALID_SOCKET) {
        std::cerr << "socket failed: " << WSAGetLastError() << "\n";
        WSACleanup();
        exit(1);
    }

    sockaddr_in serverAddress;
    memset(&serverAddress, 0, sizeof(serverAddress));
	serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(peerPort);
    inet_pton(AF_INET, peerIP.c_str(), &serverAddress.sin_addr);

    int result = connect(*sockfd,
        (SOCKADDR*)&serverAddress,
        sizeof(serverAddress));

    if (result == SOCKET_ERROR) {
        std::cerr << "connect failed: "
            << WSAGetLastError() << "\n";
        closesocket(*sockfd);
        WSACleanup();
        exit(1);
    }

    size_t sent = 0;
    while (sent < 68) {
        int n = send(*sockfd,
            message.data() + sent,
             68 - sent,
            0);
        if (n == 0) {
            std::cout << "While sending handshake: ";

            std::cerr << "connection closed by peer\n";
            exit(1);
        }
        if (n == SOCKET_ERROR) {
            std::cerr << "send failed: " << WSAGetLastError() << "\n";
            closesocket(*sockfd);
            WSACleanup();
            exit(1);
        }
        sent += n;
    }

    std::vector<uint8_t> response(68);
	char buffer[68];
    size_t received = 0;

    while (received < 68) {
        int n = recv(
            *sockfd,
            buffer + received,
            68 - received,
            0
        );

        if (n == 0) {
            // peer closed connection
			std::cout << "While receiving handshake: ";
			std::cerr << "connection closed by peer\n";
            exit(1);
        }

        if (n == SOCKET_ERROR) {
            std::cerr << "recv failed: " << WSAGetLastError() << "\n";
            exit(1);
        }

        received += n;
    }
    for (int i = 0; i < 68; i++) {
        response[i] = static_cast<uint8_t>(buffer[i]);
    }
    return response;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    std::string file_name;
    std::ifstream file;
    int command;
    std::string info;
    TorrentParser parser;
	json torrent_data;
    std::vector<uint8_t> encoded_info;
    std::vector<std::string> peers_fetched;
    SOCKET sockfd;

    unsigned char info_hash[20];

    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " decode <encoded_value>" << std::endl;
        return 1;
    }
    if (argv[1]) {
        file_name = argv[1];
        file.open(file_name, std::ios::binary);
        if (!file) {
            std::cerr << "Error opening file: " << file_name << std::endl;
            return 1;
        }
        std::filesystem::path p{ argv[1] };//path creation base
        info.assign(std::filesystem::file_size(p), '_');//buffer creation
        file.read(info.data(), std::filesystem::file_size(p));
        parser.setData(info);
        torrent_data = parser.Parse();
        encoded_info = parser.BencodeJson(torrent_data["info"]);
        sha1_wincrypt(
            encoded_info.data(),
            (DWORD)encoded_info.size(),
            info_hash
        );
    }
    else {
        return 1;
    }
    while (true) {
        clearScreen();
        std::cout << "-----------------------Welcome to BitTorrent Client-----------------------" << "\n";
        std::cout << "1.decode" << '\n';
        std::cout << "2.info" << "\n";
        std::cout << "3.peers" << '\n';
        std::cout << "4.handshake" << "\n";
        std::cout << "5.Download piece" << "\n";
        std::cout << "6.Exit" << "\n";
        std::cout << "Enter a number to select" << "\n";
        std::cin >> command;
        if (command == 1) {

            // You can use print statements as follows for debugging, they'll be visible when running tests.
            std::cerr << "Logs from your program will appear here!" << std::endl;
            try {
                std::cout << torrent_data << std::endl;
            }
            catch (const std::exception& e) {
                std::cerr << "Parser error: " << e.what() << std::endl;
                
            }
        }
        else if (command == 2) {
            std::cout << "Tracker URL : " << torrent_data["announce"] << "\nLength : " << torrent_data["info"]["length"] << "\n";
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
        else if (command == 3) {
            //read file data into buffer
             //info holds .torrent file content

            std::string tracker_url = torrent_data["announce"].get<std::string>();
            //http://127.0.0.1:5173/announce
            //scheme : http:// 
            //hostport : 127.0.0.1:5173
            //port : 5173
            //host: 127.0.0.1
            //path : announce

            auto scheme_pos = tracker_url.find("://");
            auto rest = (scheme_pos == std::string::npos) ? tracker_url : tracker_url.substr(scheme_pos + 3);
            auto slash_pos = rest.find('/');
            auto hostport = rest.substr(0, slash_pos);
            std::string path = (slash_pos == std::string::npos) ? "/" : rest.substr(slash_pos);
            std::string host = hostport;
            int port = 80;
            auto colon = hostport.find(":");
            if (colon != std::string::npos) {
                host = host.substr(0, colon);
                port = std::stoi(host.substr(colon + 1));
            }

            httplib::Client cli(host, port);

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
            std::cout << "Response status: " << res->status << '\n';
            std::string const& response_body = res->body;
            TorrentParser BencodeResponseParser;
			BencodeResponseParser.setData(response_body);
            json decoded_response = BencodeResponseParser.Parse();

            std::string const& peers = decoded_response.at("peers");

            for (size_t idx = 0; idx < peers.size(); idx += 6)
            {
                const unsigned char* p = reinterpret_cast<const unsigned char*>(peers.data() + idx);
                uint16_t port = (static_cast<uint16_t>(p[4]) << 8) | p[5]; // network byte order
                std::cout << static_cast<int>(p[0]) << '.'
                    << static_cast<int>(p[1]) << '.'
                    << static_cast<int>(p[2]) << '.'
                    << static_cast<int>(p[3]) << ':'
                    << port << std::endl;
                
                if(peers_fetched.size() < peers.size() / 6){
                    std::string ip_port =
                        std::to_string(p[0]) + "." +
                        std::to_string(p[1]) + "." +
                        std::to_string(p[2]) + "." +
                        std::to_string(p[3]) + ":" +
                        std::to_string(port);
					
                    peers_fetched.push_back(ip_port);
				}
              
              
            }
            

        }
        else if (command == 4) {
            std::vector<char> message;

            // 1 byte: protocol length
            message.push_back(19);

            // 19 bytes: protocol string
            const char* proto = "BitTorrent protocol";
            message.insert(message.end(), proto, proto + 19);

            // 8 bytes: reserved
            message.insert(message.end(), 8, 0);

            // 20 bytes: raw info_hash
            message.insert(message.end(), info_hash, info_hash+20);

            // 20 bytes: peer_id
            const char* peer_id = "-CC0001-123456789012";
            message.insert(message.end(), peer_id, peer_id + 20);

            
            assert(message.size() == 68);


            //find peer IP and port
            if (peers_fetched.size()) {//valid pieces exist
				std::cout << peers_fetched.size() << " peers fetched\n";
                size_t idx = rand() % peers_fetched.size();
                size_t ip_port_length = peers_fetched[idx].length();
                size_t colon_pos = peers_fetched[idx].find(":");
                std::string ip = peers_fetched[idx].substr(0,colon_pos);
                size_t port = std::stoul(peers_fetched[idx].substr(colon_pos+1));

				std::cout << "Making handshake to " << ip << ":" << port << std::endl;
                std::vector<uint8_t> response = make_handshake(message,ip,port,&sockfd);
				std::cout << "Received Handshake:\n";
                for(int i = 48;i < 68;i++){
                    printf("%02x",response[i]);
				}
            }
        }
        else if (command == 5) {

        }
        else if (command == 6) {
            exit(0);
        }
        else {
            std::cout << "unknown command: " << command << std::endl;
            
        }
		std::cout << "\nPress Enter to continue...";
        std::string dummy;
        std::getline(std::cin, dummy);
        std::cin.get();
    }

    return 0;
}
