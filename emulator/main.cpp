#include <iostream>

#include "emulator.h"

int main(int argc, char *argv[]) {

    Emulator* e;
    std::string input_file;

    try {
        // Provera argumenata
        if (argc != 2) {
            throw std::invalid_argument("Program expected two arguments but receives " + std::to_string(argc));
        }

        input_file = argv[1];

        if (input_file.substr(input_file.length() - 4, 4) != ".hex") {
            throw std::invalid_argument("Input file format is invalid [must be .hex]");
        }

        std::cout << "Program: " << argv[0] << std::endl;
        std::cout << "Input file: " << input_file << std::endl;

        e = new Emulator(input_file);

        e->loadMemory();

        e->emulate();

        e->displayState();

        delete e;
    }
    catch (std::exception& e) {
        std::cout << "ERROR!" << std::endl;
        std::cout << e.what() << std::endl;
    }

    return 0;
}
