#include <iostream>
#include <string>
#include <vector>
#include <cctype>
#include <cstdlib>

#include "lib/nlohmann/json.hpp"

using json = nlohmann::json;

json decode_bencoded_string(const std::string& encoded_value) {
    size_t colon_index = encoded_value.find(':');
    if (colon_index != std::string::npos) {
        std::string number_string = encoded_value.substr(0, colon_index);
        int64_t number = std::atoll(number_string.c_str());
        std::string str = encoded_value.substr(colon_index + 1, number);
        return json(str);
    }else {
        throw std::runtime_error("Invalid encoded value: " + encoded_value);
     }
}

json decode_bencoded_integer(const std::string& encoded_value) {
    return json(std::stol(encoded_value.substr(1, encoded_value.length() - 2)));

}

json decode_bencoded_dictionary(const std::string& encoded_dict) {
    json res = json::object();
    for (int i = 1; i < encoded_dict.length() - 1;) {
       
            //d3:foo3:bar5:helloi52ee
            //0123456789 
            //string : int
            //string : string
            int colon = encoded_dict.find(':', i);//2
            json value;
            int len = std::stoi(encoded_dict.substr(i,colon-i));//3
            json key = decode_bencoded_string(encoded_dict.substr(i,len+2));//3:foo i = 1 
            i +=  len + 2;
            if (encoded_dict[i] == 'i') {
				int finish_idx = encoded_dict.find('e', i);
                value = decode_bencoded_integer(encoded_dict.substr(i,finish_idx-i + 1));
				i = finish_idx + 1;
            }
            else {
                int colon_value = encoded_dict.find(':', i);
                int len_value = std::stoi(encoded_dict.substr(i, colon_value - i));
				value = decode_bencoded_string(encoded_dict.substr(i,  2 + len_value));
                i += len_value + 2;
            }
           
            res[key.get<std::string>()] = value;
    }
    return res;

}

json decode_bencoded_list(const std::string& encoded_list) {
    std::vector<json> result;

    for (size_t i = 1; i < encoded_list.length() - 1; ) {

        if (encoded_list[i] == 'i') { // integer
            int finish_idx = encoded_list.find('e', i);
            result.push_back(
                decode_bencoded_integer(
                    encoded_list.substr(i, finish_idx - i + 1)
                )
            );
            i = finish_idx + 1;
        }
        else if (std::isdigit(encoded_list[i])) { // string
            int colon = encoded_list.find(':', i);
            int len = std::stoi(encoded_list.substr(i, colon - i));

            result.push_back(
                decode_bencoded_string(
                    encoded_list.substr(i, (colon - i) + 1 + len)
                )
            );

            i = colon + 1 + len;
        }
    }

    return result;
}

json decode_bencoded_value(const std::string& encoded_value) {
    if (std::isdigit(encoded_value[0])) {
        // Example: "5:hello" -> "hello"
		   return decode_bencoded_string(encoded_value);
    }
    else if (encoded_value[0] == 'i' && encoded_value.back() == 'e') {
		return decode_bencoded_integer(encoded_value);
    }
    else if (encoded_value[0] == 'l' && encoded_value.back() == 'e') {
        return decode_bencoded_list(encoded_value);
    }else if(encoded_value[0] == 'd' && encoded_value.back() == 'e') {
        return decode_bencoded_dictionary(encoded_value);
	}
    else {
        throw std::runtime_error("Unhandled encoded value: " + encoded_value);
    }
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

        // TODO: Uncomment the code below to pass the first stage
         std::string encoded_value = argv[2];
         json decoded_value = decode_bencoded_value(encoded_value);
         std::cout << decoded_value.dump() << std::endl;
    } else {
        std::cerr << "unknown command: " << command << std::endl;
        return 1;
    }

    return 0;
}
