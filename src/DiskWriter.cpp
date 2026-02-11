#include <fstream>
#include <iostream>
#include <filesystem>
#include <vector>
#include <mutex>
#include <json.hpp>
#include <DiskWriter.h>



DiskWriter::DiskWriter(const nlohmann::json& torrent_data,
        const std::string& out)
        : torrent(torrent_data), output_path(out){

        pieceLength = torrent["info"]["piece length"].get<uint64_t>();

        if (torrent["info"].contains("length")) {
            // SINGLE FILE 
            FileEntry fe;
            fe.length = torrent["info"]["length"].get<uint64_t>();
            fe.offset = 0;

            std::string name = torrent["info"]["name"];
            fe.path = output_path + "/" + name;

            prepareFile(fe);
            files.push_back(std::move(fe));
        }
        else {
            // MULTI FILE
            uint64_t offset = 0;

            for (auto& f : torrent["info"]["files"]) {
                FileEntry fe;
                fe.length = f["length"].get<uint64_t>();
                fe.offset = offset;

                // build path
                std::string path = output_path + "/" +
                    torrent["info"]["name"].get<std::string>() + "/";

                for (auto& p : f["path"]) {
                    path += p.get<std::string>() + "/";
                }
                path.pop_back(); // remove trailing /

                fe.path = path;

                prepareFile(fe);
                files.push_back(std::move(fe));

                offset += fe.length;
            }
        }
}

    // ----------------------------------------------------


    //piece
    // 0 : 300 bytes
    // 1 : 300 bytes//600 bytes
    // 2 : 600 bytes//900
    // 4 : 900 bytes//1200
    //5 :  1200 bytes//1250
    //1200+150 =  1350

    //files
    //a/1.txt = 0 to 200(200)bytes --> 200 
    //b/2.txt = 200 to 600(400) bytes --> 600
    //c/3.txt = 600 to 800(200) --> 800
    //d/4.txt = 800 to 1350(550) --> 1350


bool DiskWriter::WritePiece(int pieceIndex,
        const char* buffer,
        size_t bufferSize){
    
        std::lock_guard<std::mutex> lock(diskMutex);

        uint64_t pieceStart = (uint64_t)pieceIndex * pieceLength;
        uint64_t pieceEnd = pieceStart + bufferSize;

        for (auto& file : files) {

            uint64_t fileStart = file.offset;
            uint64_t fileEnd = file.offset + file.length;

            // no overlap
            if (pieceEnd <= fileStart || pieceStart >= fileEnd)
                continue;

            uint64_t writeStart = std::max(pieceStart, fileStart);
            uint64_t writeEnd = std::min(pieceEnd, fileEnd);

            uint64_t fileOffset = writeStart - fileStart;
            uint64_t bufferOffset = writeStart - pieceStart;
            uint64_t writeLen = writeEnd - writeStart;

            file.stream.seekp(fileOffset);
            file.stream.write(
                buffer + bufferOffset,
                writeLen
            );

            if (!file.stream.good()) {
                std::cerr << "Disk write failed: " << file.path << "\n";
                return false;
            }
        }

        return true;
}


void DiskWriter::prepareFile(FileEntry& fe){

        std::filesystem::path p(fe.path);

        if (!p.parent_path().empty()) {
            std::filesystem::create_directories(p.parent_path());
        }

        // create + size file
        {
            std::ofstream create(fe.path, std::ios::binary);
            create.seekp(fe.length - 1);
            create.write("", 1);
        }

        fe.stream.open(
            fe.path,
            std::ios::in | std::ios::out | std::ios::binary
        );
}

