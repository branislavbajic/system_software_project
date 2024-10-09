#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

#include "emulator.h"

#define PC 15
#define SP 14

#define STATUS 0
#define HANDLER 1
#define CAUSE 2

Emulator::Emulator(std::string  in) : input_file(std::move(in)) {

    cpu_context = std::make_unique<CPU>();
    cpu_context->reg[0] = 0; // Registar r0 je ozicen na vrednost nula
    cpu_context->reg[SP] = 0xFFFFFFFF; // SP postavljamo na najvisu adresu
    cpu_context->reg[PC] = 0x40000000; // Program krece od ove adrese

}

void Emulator::trim(std::string& line, const std::string& additional) {
    while(!line.empty() && (isspace(line[0]) || additional.find(line[0]) != std::string::npos)) {
        line.erase(0,1);
    }
    while(!line.empty() && (isspace(line[line.length() - 1]) || additional.find(line[line.length() - 1]) != std::string::npos)) {
        line.erase(line.length() - 1,1);
    }
}

int Emulator::twosComplement(unsigned int unsigned_value, int num_of_bits) {

    std::stringstream ss;
    std::string s_value;
    int neg_check_value = 1 << (num_of_bits - 1), result;
    size_t idx;

    bool is_negative = unsigned_value & neg_check_value;

    char fill = is_negative ? 'f' : '0';

    ss << "0x" << std::hex << std::setw(8) << std::setfill(fill) << unsigned_value;
    ss >> s_value;

    result = static_cast<int>(stol(s_value, &idx, 16));

    return result;

}

void Emulator::loadMemory() {

    std::fstream ifs(input_file, std::ios::in);
    std::string line, data;
    unsigned int address;
    int value;
    size_t idx;
    std::stringstream ss;

    if (!ifs.is_open()) {
        throw std::runtime_error("Input file not found!");
    }

    while (!ifs.eof()) {

        bool address_valid = true;
        getline(ifs, line);

        data = line.substr(0, 9);

        if (data.empty()) {
            continue; // preskakanje praznih redova
        }

        trim(data, ":");
        line.erase(0, 10);

        try {
            address = std::stol(data, &idx, 16);
        }
        catch (std::exception& err) {
            address_valid = false;
        }

        if (!address_valid || idx != data.length()) {
            throw std::invalid_argument("Address is not a valid number! --> " + data);
        }

        unsigned int offset = 0;

        ss.str(line);
        while (getline(ss, data, ' ')) {
            bool data_valid = true;
            try {
                value = (int) std::stol(data, &idx, 16);
            }
            catch(std::exception& err) {
                data_valid = false;
            }

            if (!data_valid || idx != data.length()) {
                throw std::invalid_argument("Data is not a valid number! --> " + data);
            }

            std::pair<int, bool> new_entry;

            new_entry.first = value;
            new_entry.second = false;

            source_memory[address + offset++] = new_entry;
        }
        ss.clear();
    }

}

void Emulator::emulate() {

    bool emulation = true;
    unsigned int temp;
    int signed_value1, signed_value2;
    std::string op_code_string;

    while (emulation) {

        unsigned int pc = cpu_context->reg[PC], read_address;
        std::stringstream ss_test;
        ss_test << std::hex << std::setw(8) << std::setfill('0') << pc;
        std::string address;
        ss_test >> address;
        ss_test.clear();


        std::stringstream ss;

        if (source_memory.find(pc) == source_memory.end()) {
            throw std::runtime_error("Segmentation fault! Executing code from illegal address!");
        }

        unsigned int op_code = (source_memory.at(pc + 0).first >> 4) & 0x0f;
        unsigned int mode = source_memory.at(pc + 0).first & 0x0f;

        ss << std::hex << std::setw(2) << std::setfill('0') << source_memory.at(pc + 0).first;
        ss >> op_code_string;

        int regA = (source_memory.at(pc + 1).first >> 4) & 0x0f;
        int regB = source_memory.at(pc + 1).first & 0x0f;

        int regC = (source_memory.at(pc + 2).first >> 4) & 0x0f;
        int disp1 = source_memory.at(pc + 2).first & 0x0f;

        int disp2 = (source_memory.at(pc + 3).first >> 4) & 0x0f;
        int disp3 = source_memory.at(pc + 3).first & 0x0f;

        unsigned int unsigned_12bit_value = (disp1 << 8) | (disp2 << 4) | disp3;
        int displacement = twosComplement(unsigned_12bit_value, 12);

        cpu_context->reg[PC] += 4;

        switch (op_code) {

            // Instrukcija za zaustavljanje procesora
            case 0b0000:

                // dodati proveru moda (na primer, iako je prvi nibble 0, drugi moze da bude != 0, sto nije dozvoljeno)

                if (mode != 0b0000) {
                    throw std::runtime_error("Invalid operation code! --> " + op_code_string);
                }

                std::cout << "Emulated processor executed halt instruction" << std::endl;
                emulation = false;

                break;

            // Instrukcija softverskog prekida
            case 0b0001:

                if (mode != 0b0000) {
                    throw std::runtime_error("Invalid operation code! --> " + op_code_string);
                }

                pushToStack(cpu_context->csr[STATUS]);

                pushToStack(cpu_context->reg[PC]);

                cpu_context->csr[CAUSE] = 4;

                cpu_context->csr[STATUS] &= (~0x1);

                cpu_context->reg[PC] = cpu_context->csr[HANDLER];

                break;

            // Instrukcija poziva potprograma
            case 0b0010:

                switch (mode) {

                    case 0b0000:

                        pushToStack(cpu_context->reg[PC]);
                        cpu_context->reg[PC] = cpu_context->reg[regA] + cpu_context->reg[regB] + displacement;
                        break;

                    case 0b0001:

                        read_address = cpu_context->reg[regA] + cpu_context->reg[regB] + displacement;
                        pushToStack(cpu_context->reg[PC]);
                        cpu_context->reg[PC] = readFromMemory(read_address);

                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            // Instrukcija skoka
            case 0b0011:

                read_address = cpu_context->reg[regA] + displacement;

                switch(mode) {

                    case 0b0000:

                        cpu_context->reg[PC] = cpu_context->reg[regA] + displacement;

                        break;

                    case 0b0001:

                        if (cpu_context->reg[regB] == cpu_context->reg[regC]) {
                            cpu_context->reg[PC] = cpu_context->reg[regA] + displacement;
                        }

                        break;

                    case 0b0010:

                        if (cpu_context->reg[regB] != cpu_context->reg[regC]) {
                            cpu_context->reg[PC] = cpu_context->reg[regA] + displacement;
                        }

                        break;

                    case 0b0011:

                        signed_value1 = twosComplement(cpu_context->reg[regB], 32);
                        signed_value2 = twosComplement(cpu_context->reg[regC], 32);

                        if (signed_value1 > signed_value2) {
                            cpu_context->reg[PC] = cpu_context->reg[regA] + displacement;
                        }

                        break;

                    case 0b1000:

                        cpu_context->reg[PC] = readFromMemory(read_address);

                        break;

                    case 0b1001:

                        if (cpu_context->reg[regB] == cpu_context->reg[regC]) {
                            cpu_context->reg[PC] = readFromMemory(read_address);
                        }

                        break;

                    case 0b1010:

                        if (cpu_context->reg[regB] != cpu_context->reg[regC]) {
                            cpu_context->reg[PC] = readFromMemory(read_address);
                        }

                        break;

                    case 0b1011:

                        signed_value1 = twosComplement(cpu_context->reg[regB], 32);
                        signed_value2 = twosComplement(cpu_context->reg[regC], 32);

                        if (signed_value1 > signed_value2) {
                            cpu_context->reg[PC] = readFromMemory(read_address);
                        }

                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            // Instrukcija atomicne zamene vrednosti
            case 0b0100:

                if (mode != 0b0000) {
                    throw std::runtime_error("Invalid operation code! --> " + op_code_string);
                }

                temp = cpu_context->reg[regB];
                cpu_context->reg[regB] = cpu_context->reg[regC];
                cpu_context->reg[regC] = temp;

                break;

            // Instrukcija aritmetickih operacija
            case 0b0101:

                switch (mode) {

                    case 0b0000:

                        cpu_context->reg[regA] = cpu_context->reg[regB] + cpu_context->reg[regC];

                        break;

                    case 0b0001:

                        cpu_context->reg[regA] = cpu_context->reg[regB] - cpu_context->reg[regC];

                        break;

                    case 0b0010:

                        cpu_context->reg[regA] = cpu_context->reg[regB] * cpu_context->reg[regC];

                        break;

                    case 0b0011:

                        cpu_context->reg[regA] = cpu_context->reg[regB] / cpu_context->reg[regC];

                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            // Instrukcija logickih operacija
            case 0b0110:

                switch (mode) {

                    case 0b0000:

                        cpu_context->reg[regA] = ~(cpu_context->reg[regB]);

                        break;

                    case 0b0001:

                        cpu_context->reg[regA] = cpu_context->reg[regB] & cpu_context->reg[regC];

                        break;

                    case 0b0010:

                        cpu_context->reg[regA] = cpu_context->reg[regB] | cpu_context->reg[regC];

                        break;

                    case 0b0011:

                        cpu_context->reg[regA] = cpu_context->reg[regB] ^ cpu_context->reg[regC];

                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            // Instrukcija pomerackih operacija
            case 0b0111:

                switch (mode) {

                    case 0b000:

                        cpu_context->reg[regA] = cpu_context->reg[regB] << cpu_context->reg[regC];

                        break;

                    case 0b0001:

                        cpu_context->reg[regA] = cpu_context->reg[regB] >> cpu_context->reg[regC];

                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            // Instrukcija smestanja podataka
            case 0b1000:

                switch (mode) {

                    case 0b0000:

                        read_address = cpu_context->reg[regA] + cpu_context->reg[regB] + displacement;
                        writeToMemory(read_address, cpu_context->reg[regC]);

                        break;

                    case 0b0010:

                        read_address = cpu_context->reg[regA] + cpu_context->reg[regB] + displacement;
                        temp = readFromMemory(read_address);

                        writeToMemory(temp, cpu_context->reg[regC]);

                        break;

                    case 0b0001:

                        // Kreiranje ulaza u memoriji za potencijalni rast steka

                        if (source_memory.find(cpu_context->reg[SP] - 4) != source_memory.end()) {
                            if (!source_memory.at(cpu_context->reg[SP] - 4).second) {
                                throw std::runtime_error("Segmentation fault! Stack overlaps program code/data!");
                            }
                            // stek je vec rastao do ove adrese
                        }
                        else {
                            // stek do sada nije rastao do ove adrese i ona ne pripada kodu/podacima
                            for (int i = 0; i < 4; i++) {

                                std::pair<int, bool> new_entry;
                                new_entry.first = 0;
                                new_entry.second = true;

                                unsigned int addr = cpu_context->reg[SP] - 4 + i;
                                source_memory[addr] = new_entry;
                            }
                        }

                        cpu_context->reg[regA] += displacement;

                        writeToMemory(cpu_context->reg[regA], cpu_context->reg[regC]);


                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            // Instrukcija ucitavanja podataka
            case 0b1001:

                switch (mode) {

                    case 0b0000:

                        cpu_context->reg[regA] = cpu_context->csr[regB];

                        break;

                    case 0b0001:

                        cpu_context->reg[regA] = cpu_context->reg[regB] + displacement;

                        break;

                    case 0b0010:

                        read_address = cpu_context->reg[regB] + cpu_context->reg[regC] + displacement;

                        cpu_context->reg[regA] = readFromMemory(read_address);

                        break;

                    case 0b0011:

                        read_address = cpu_context->reg[regB];

                        cpu_context->reg[regA] = readFromMemory(read_address);
                        cpu_context->reg[regB] += displacement;

                        break;

                    case 0b0100:

                        cpu_context->csr[regA] = cpu_context->reg[regB];

                        break;

                    case 0b0101:

                        cpu_context->csr[regA] = cpu_context->csr[regB] | displacement;

                        break;

                    case 0b0110:

                        read_address = cpu_context->reg[regB] + cpu_context->reg[regC] + displacement;
                        cpu_context->csr[regA] = readFromMemory(read_address);

                        break;

                    case 0b0111:

                        read_address = cpu_context->reg[regB];

                        cpu_context->csr[regA] = readFromMemory(read_address);
                        cpu_context->reg[regB] += displacement;

                        break;

                    default:

                        throw std::runtime_error("Invalid operation code! --> " + op_code_string);

                }

                break;

            default:

                throw std::runtime_error("Invalid operation code! --> " + op_code_string);


        }

    }

}

void Emulator::displayState() const {

    std::cout << "Emulated processor state: " << std::endl;
    for (int i = 0; i < 16; i++) {
        std::cout << "r" << std::dec << i << "=0x" << std::hex << std::setw(8) << std::setfill('0') << cpu_context->reg[i];

        if ((i + 1) % 4 == 0) {
            std::cout << std::endl;
        }
        else {
            std::cout << "\t";
        }
    }

    std::cout << "\nMemory state:" << std::endl;
    for (auto& pair: source_memory) {
        std::cout << std::hex << std::setw(8) << std::setfill('0') << pair.first << " : ";
        std::cout << std::hex << std::setw(2) << std::setfill('0') << pair.second.first << std::endl;
    }


}

unsigned int Emulator::readFromMemory(unsigned int address) {

    unsigned int value;
    int hex_num[4];

    for (int i = 0; i < 4; i++) {
        if (source_memory.find(address + i) == source_memory.end()) {
            throw std::runtime_error("Segmentation fault! Reading from address without permission!");
        }

        hex_num[i] = source_memory.at(address + i).first;
    }

    value = (hex_num[3] << 24) | (hex_num[2] << 16) | (hex_num[1] << 8) | hex_num[0];

    return value;

}

void Emulator::writeToMemory(unsigned int address, unsigned int value) {

    int hex_num[4];
    int num, increment = 2;
    std::stringstream ss1;
    std::string s;

    ss1 << std::hex << std::setw(8) << std::setfill('0') << value;
    ss1 >> s;

    for (int i = 0; i < 4; i++) {
        std::stringstream ss2;
        std::string temp = s.substr(i * increment, increment);
        ss2 << temp;
        ss2 >> std::hex >> num;
        hex_num[i] = num;
    }

    int j = 3;
    for (int i = 0; i < 4; i++) {
        if (source_memory.find(address + i) == source_memory.end()) {
            throw std::runtime_error("Segmentation fault! Writing to address without permission!");
        }

        source_memory.at(address + i).first = hex_num[j--];
    }

}

void Emulator::pushToStack(unsigned int value) {

    cpu_context->reg[SP] -= 4;
    unsigned int sp = cpu_context->reg[SP];

    if (source_memory.find(sp) != source_memory.end()) {
        if (!source_memory.at(sp).second) {
            throw std::runtime_error("Segmentation fault! Stack overlaps program code/data!");
        }
        // stek je vec rastao do ove adrese
    }
    else {
        // stek do sada nije rastao do ove adrese i ona ne pripada kodu/podacima
        for (int i = 0; i < 4; i++) {

            std::pair<int, bool> new_entry;
            new_entry.first = 0;
            new_entry.second = true;

            source_memory[sp + i] = new_entry;
        }
    }

    writeToMemory(sp, value);
}