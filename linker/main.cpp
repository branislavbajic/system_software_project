#include <iostream>
#include <string>
#include <regex>
#include <list>

#include "linker.h"

int main(int argc, char* argv[]) {

    Linker* l;
    bool hex_option = false, relocatable_option = false, if_exist = false, of_exist = false;
    std::string output_file;
    std::list<std::string> input_files;
    std::list<std::pair<std::string, unsigned int>> section_places;
    size_t idx;

    std::regex FILE(R"(^[A-Za-z0-9_-]*\.[A-Za-z0-9]*$)");
    std::regex PLACE(R"(^-place=([A-Za-z0-9_.]*)\@(0x[A-Za-z0-9_]+)$)");
    std::regex TYPE(R"(^\-[A-Za-z]+$)");
    std::smatch match;

    try {
        for (int i = 1; i < argc; i++) {

            std::string arg = argv[i];

            if (std::regex_match(arg, match, FILE)) {

                const std::string& file = arg;
                std::string previous = argv[i - 1];

                if (previous == "-o") { // output file
                    if (of_exist) {
                        throw std::logic_error("Multiple output files!");
                    }
                    output_file = file;
                    of_exist = true;
                }
                else { // input file
                    if (file.substr(file.length() - 2, 2) != ".o") {
                        throw std::logic_error("Wrong input file extension!");
                    }

                    input_files.push_back(file);
                    if_exist = true;
                }

            }
            else if (std::regex_match(arg, match, PLACE)) {

                std::string section_name = match[1];
                std::string addr = match[2];

                for (auto& elem: section_places) {
                    if (elem.first == section_name) {
                        throw std::logic_error("Can't have -place option with same section name twice!!");
                    }
                }

                std::pair<std::string, unsigned int> elem;
                elem.first = section_name;
                elem.second = stol(addr, &idx, 16);

                auto it = section_places.begin();

                while (it != section_places.end()) {
                    if ((*it).second > elem.second) {
                        break;
                    }
                    it++;
                }

                section_places.emplace(it, elem);

            }
            else if (std::regex_match(arg, match, TYPE)) {

                std::string type = match[0];

                if (type == "-hex") {

                    if (hex_option) {
                        throw std::logic_error("Multiple -hex options!");
                    }

                    if (relocatable_option) {
                        throw std::logic_error("Can't have both -hex and -relocatable options!");
                    }

                    hex_option = true;
                }
                else if (type == "-relocatable") {
                    if (relocatable_option) {
                        throw std::logic_error("Multiple -relocatable options!");
                    }

                    if (hex_option) {
                        throw std::logic_error("Can't have both -hex and -relocatable options!");
                    }

                    relocatable_option = true;
                }
                else if (type != "-o") {
                    throw std::logic_error("Unknown type: " + type);
                }

            }
            else {
                throw std::logic_error("Invalid argument: " + arg);
            }

        }

        if (!of_exist) {
            throw std::logic_error("Output file missing!");
        }

        if (!if_exist) {
            throw std::logic_error("You need at least one input file!");
        }

        if (!hex_option && !relocatable_option) {
            throw std::logic_error("Output file type not specified (-hex or -relocatable)!");

        }

        l = new Linker(output_file, input_files, section_places);

        l->symbolResolution();

        l->relocation();

        l->createOutputFile();

        delete l;
    }
    catch (std::exception& e) {
        std::cout << "ERROR!" << std::endl;
        std::cout << e.what() << std::endl;
    }

    return 0;
}
