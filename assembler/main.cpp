#include <iostream>
#include <string>

#include "assembler.h"


int main(int argc, char *argv[]) {

    Assembler* a;
    std::string input_file, output_file, option;

    try {
        if (argc != 4) {
            throw std::invalid_argument("Invalid argument count!");
        }

        option = argv[1];
        output_file = argv[2];
        input_file = argv[3];

        if (option != "-o") {
            throw std::invalid_argument("Option " + option + " not recognized!");
        }

        if (output_file.substr(output_file.length() - 2, 2) != ".o" || input_file.substr(input_file.length() - 2, 2) != ".s") {
            throw std::invalid_argument("Invalid file format!");
        }

        std::cout << "Program: " << argv[0] << std::endl;
        std::cout << "Options: " << option << std::endl;
        std::cout << "Input file: " << input_file << std::endl;
        std::cout << "Output file: " << output_file << std::endl;

        a = new Assembler(input_file, output_file);

        a->processInputFile();

        a->createOutputFile();

        delete a;
    }
    catch (std::exception& e) {
        std::cout << "ERROR!" << std::endl;
        std::cout << e.what() << std::endl;
    }

    return 0;
}
