#include <iostream>
#include <string>
#include <vector>
#include <json.hpp>
#include <TorrentParser.h>

using json = nlohmann::json;

    //integer
    // 
json TorrentParser::parseBInt() {

        pos++; // skip i

        size_t start = pos;
        while (pos < data.size() && data[pos] != 'e')
            pos++;

        if (pos >= data.size())
            throw std::runtime_error("Unterminated integer");

        long long val = std::stoll(data.substr(start, pos - start));
        pos++; // consume e
        return json(val);

}

    //  string
json TorrentParser::parseBString() {

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

    // List 
json TorrentParser::parseBList() {
        pos++; // skip l
        json list = json::array();

        while (pos < data.size() && data[pos] != 'e') {
            list.push_back(Parse());
        }

        if (pos >= data.size())
            throw std::runtime_error("Unterminated list");

        pos++; // consume e
        return list;
}

    //  Dictionary 
json TorrentParser::parseBDict() {

        pos++; // skip d
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

        pos++; // consume e
        return dict;
}


    TorrentParser::TorrentParser(){}

void TorrentParser::setData(const std::string& input) {
        data = input;
        pos = 0;
}

json TorrentParser::Parse() {
        if (pos >= data.size())
            throw std::runtime_error("Unexpected end of data");

        char c = data[pos];

        if (c == 'i') return parseBInt();
        if (c == 'l') return parseBList();
        if (c == 'd') return parseBDict();
        if (std::isdigit(c)) return parseBString();


        throw std::runtime_error(std::string("Invalid bencode char: ") + c);
}

std::vector<uint8_t> TorrentParser::BencodeJson(const json& j) {

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

std::string TorrentParser::url_encode_bytes(unsigned char* url) {

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