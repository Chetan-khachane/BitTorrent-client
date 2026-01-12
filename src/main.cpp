#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <filesystem>
#include "lib/nlohmann/json.hpp"
#include <variant>
#include <unordered_map>
#include <windows.h>
#include <wincrypt.h>

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

//json decode_bencoded_string(const std::string& encoded_value) {
//    size_t colon_index = encoded_value.find(':');
//    if (colon_index != std::string::npos) {
//        std::string number_string = encoded_value.substr(0, colon_index);
//        int64_t number = std::atoll(number_string.c_str());
//        std::string str = encoded_value.substr(colon_index + 1, number);
//        return json(str);
//    }else {
//        throw std::runtime_error("Invalid encoded value: " + encoded_value);
//     }
//}
//
//json decode_bencoded_integer(const std::string& encoded_value) {
//    return json(std::stol(encoded_value.substr(1, encoded_value.length() - 2)));
//
//}
//
//json decode_bencoded_dictionary(const std::string& encoded_dict) {
//    json res = json::object();
//    for (int i = 1; i < encoded_dict.length() - 1;) {
// 
//            int colon = encoded_dict.find(':', i);//2
//            json value;
//            int len = std::stoi(encoded_dict.substr(i,colon-i));//3
//            json key = decode_bencoded_string(encoded_dict.substr(i,len+2));//3:foo i = 1 
//            i +=  len + 2;
//            if (encoded_dict[i] == 'i') {
//				int finish_idx = encoded_dict.find('e', i);
//                value = decode_bencoded_integer(encoded_dict.substr(i,finish_idx-i + 1));
//				i = finish_idx + 1;
//            }
//            else {
//                int colon_value = encoded_dict.find(':', i);
//                int len_value = std::stoi(encoded_dict.substr(i, colon_value - i));
//				value = decode_bencoded_string(encoded_dict.substr(i,  2 + len_value));
//                i += len_value + 2;
//            }
//           
//            res[key.get<std::string>()] = value;
//    }
//    return res;
//
//
//}
////list : l
////dict : d
////int : i
////string : number : 
//
//std::vector<json> decode_bencoded_list(const std::string& encoded_list) {
//    std::vector<json> result;
//
//    //for (size_t i = 1; i < encoded_list.length() - 1; ) {
//
//    //    if (encoded_list[i] == 'i') { // integer
//    //        int finish_idx = encoded_list.find('e', i);
//    //        result.push_back(
//    //            decode_bencoded_integer(
//    //                encoded_list.substr(i, finish_idx - i + 1)
//    //            )
//    //        );
//    //        i = finish_idx + 1;
//    //    }
//    //    else if (std::isdigit(encoded_list[i])) { // string
//    //        int colon = encoded_list.find(':', i);
//    //        int len = std::stoi(encoded_list.substr(i, colon - i));
//
//    //        result.push_back(
//    //            decode_bencoded_string(
//    //                encoded_list.substr(i, (colon - i) + 1 + len)
//    //            )
//    //        );
//
//    //        i = colon + 1 + len;
//    //    }
//    //}
//    for (int i = 1; i < encoded_list.length() - 1;) {
//        if (encoded_list[i] == 'i') {//integer
//            int finish_idx = encoded_list.find('e',i);
//            result.push_back(decode_bencoded_integer(encoded_list.substr(i,finish_idx-i+1)));
//            i = finish_idx + 1;
//        }
//        else if (encoded_list[i] == 'l') {//list
//
//        }
//        else if (encoded_list[i] == 'd') {//dictionary
//
//        }
//        else {//string
//
//        }
//    }
//    return result;
//}
//
////parse_bencode
//
//json parse_bencode(const std::string& encoded_value) {
//    if (std::isdigit(encoded_value[0])) {
//        // Example: "5:hello" -> "hello"
//		   return decode_bencoded_string(encoded_value);
//    }
//    else if (encoded_value[0] == 'i' && encoded_value.back() == 'e') {
//		return decode_bencoded_integer(encoded_value);
//    }
//    else if (encoded_value[0] == 'l' && encoded_value.back() == 'e') {
//        return decode_bencoded_list(encoded_value);
//    }else if(encoded_value[0] == 'd' && encoded_value.back() == 'e') {
//        return decode_bencoded_dictionary(encoded_value);
//	}
//    else {
//        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
//    }
//}

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
            // IMPORTANT: handles "pieces" correctly
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
        
        std::cout << "Tracker URL : " << torrent_data["announce"] << "Length : "<<torrent_data["info"]["length"] << "\n";
        std::cout << "Info Hash: ";
        for (int i = 0; i < 20; i++) {
            printf("%02x", info_hash[i]);
        }
		std::cout << std::endl;
    }
    else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
