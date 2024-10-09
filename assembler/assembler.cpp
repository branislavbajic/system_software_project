#include <iostream>
#include <fstream>
#include <sstream>
#include <regex>
#include <iomanip>
#include <string>
#include <algorithm>
#include <cstdlib>

#include "assembler.h"

#define MAX_DISP 2044

Assembler::Assembler(std::string in, std::string out) : input_file(std::move(in)), output_file(std::move(out)) {
    symtab = new SymTab();
    current_section = "";
    location_counter = 0;
    line_num = 0;
}

// TO DO: Brisanje alocirane memorije na koju ne pokazuje smart pointer
Assembler::~Assembler() {
    for (auto& section_name: section_order) {
        Section* section = section_table.at(section_name);
        delete section;
    }

    delete symtab;
}

void Assembler::trim(std::string& line, const std::string& additional) {
    while(!line.empty() && (isspace(line[0]) || additional.find(line[0]) != std::string::npos)) {
        line.erase(0,1);
    }
    while(!line.empty() && (isspace(line[line.length() - 1]) || additional.find(line[line.length() - 1]) != std::string::npos)) {
        line.erase(line.length() - 1,1);
    }
}

directive Assembler::directiveStringToCode(const std::string& d) {
    if (d == ".global") return GLOBAL;
    if (d == ".extern") return EXTERN;
    if (d == ".section") return SECTION;
    if (d == ".word") return WORD;
    if (d == ".skip") return SKIP;
    if (d == ".end") return END;
    return DEFAULT_DIRECTIVE;
}

instruction Assembler::instructionStringToCode(const std::string& i) {
    if (i == "halt") return HALT;
    if (i == "int") return INT;
    if (i == "iret") return IRET;
    if (i == "call") return CALL;
    if (i == "ret") return RET;
    if (i == "jmp") return JMP;
    if (i == "beq") return BEQ;
    if (i == "bne") return BNE;
    if (i == "bgt") return BGT;
    if (i == "push") return PUSH;
    if (i == "pop") return POP;
    if (i == "xchg") return XCHG;
    if (i == "add") return ADD;
    if (i == "sub") return SUB;
    if (i == "mul") return MUL;
    if (i == "div") return DIV;
    if (i == "not") return NOT;
    if (i == "and") return AND;
    if (i == "or") return OR;
    if (i == "xor") return XOR;
    if (i == "shl") return SHL;
    if (i == "shr") return SHR;
    if (i == "ld") return LD;
    if (i == "st") return ST;
    if (i == "csrrd") return CSRRD;
    if (i == "csrwr") return CSRWR;
    return DEFAULT_INSTRUCTION;
}

void Assembler::intToHex32b(unsigned int value, int* hex_num, int number_of_parts) {

    std::stringstream ss1;
    std::string s;
    int num, increment = 8 / number_of_parts;

    ss1 << std::hex << std::setw(8) << std::setfill('0') << value;
    ss1 >> s;

    for (int i = 0; i < number_of_parts; i++) {
        std::stringstream ss2;
        std::string temp = s.substr(i * increment, increment);
        ss2 << temp;
        ss2 >> std::hex >> num;
        hex_num[i] = num;
    }

}

bool Assembler::literalCheck(const std::string& operand, unsigned int& value) {

    int base = 10;
    long val;
    size_t idx;
    std::string op = operand, prefix;
    bool is_ok = true;

    prefix = operand.substr(0, 2);

    if (prefix == "0x") {
        op = operand.substr(2, operand.length());
        base = 16;
    }
    else if (prefix == "0b") {
        op = operand.substr(2, operand.length());
        base = 2;
    }

    try {
        val = std::stol(op, &idx, base);
    }
    catch (std::exception& err) {
        is_ok = false;
    }

    if (is_ok) {
        if (idx == op.length()) {
            if (val > 0xffffffff) {
                std::string num_string;
                std::stringstream ss;

                if (base == 16) {
                    ss << "0x" << std::hex << val;
                }
                else {
                    ss << val;
                }

                ss >> num_string;

                throw std::logic_error("Numeric literal can't be bigger than 32b!\nLiteral -> " + num_string);
            }
            value = val;
            return true;
        }
    }

    return false;

}

bool Assembler::getRegnum(const std::string& reg, unsigned int& gpr, bool is_csr) {

    // RETNIK: Sta ako je unesen broj registra veci od dve cifre?
    if (!is_csr) {
        if (reg == "%sp") {
            gpr = 14;
        }
        else if (reg == "%pc") {
            gpr = 15;
        }
        else {
            if (reg.length() > 4) {
                return false;
            }
            if (reg.substr(0, 2) != "%r") {
                // greska - los format
                return false;
            }
            if (!literalCheck(reg.substr(2, reg.length() > 3 ? 2 : 1), gpr)) {
                return false;
            }
        }
    }
    else {
        if (reg == "%status") {
            gpr = 0;
        }
        else if (reg == "%handler") {
            gpr = 1;
        }
        else if (reg == "%cause") {
            gpr = 2;
        }
        else {
            return false;
        }
    }

    return true;

}

void Assembler::processLabel(std::string label) {

    if (!label.empty()) {
        if (current_section.empty()) {
            throw std::logic_error("Label definition outside sections!!\nLine: " + std::to_string(line_num) + " -> " + label);
        }

        trim(label, ":");

        if (!symtab->exist(label)) {
            symtab->addSymbol(label, location_counter, current_section, false, false, false);
            symbol_order.push_back(label);
        }
        else {
            if (symtab->getSection(label) == 0) { // dodata direktivom .global ili se našla u delu za operand
                if (symtab->isExtern(label)) {
                    throw std::logic_error("Label can't be extern!\nLine: " + std::to_string(line_num) + " -> " + label);
                }
                symtab->setAddress(label, location_counter);
                symtab->setSection(label, current_section);
            }
            else {
                if (symtab->isSectionName(label)) {
                    throw std::logic_error("Section name can't be used as an operand/label!\nLine: " + std::to_string(line_num) + " -> " + label);
                }
                throw std::logic_error("Multiple definition of symbol!\nLine: " + std::to_string(line_num) + " -> " + label);
            }
        }

        symtab->setDefined(label);
    }

}

void Assembler::createSection(bool end) {

    int hex_num[4];
    unsigned int l_pool_size, value;
    bool is_literal;
    std::unique_ptr<LiteralPool> l_pool;

    // Provera da li je neki simbol u tabeli literala u medjuvremenu definisan u istoj sekciji sa pomerajem ne dalje 0d 12b za instrukciju skoka

    auto it = literal_table.begin();

    while (it != literal_table.end()) {
        auto element = *(it);

        std::vector<unsigned int> new_vector;
        if (symtab->isDefined(element.first) && symtab->getSection(element.first) == symtab->getSection(current_section)) {

            for (auto& addr: element.second) {
                // provera da li je instrukcija skoka ili poziva potprograma i odrediste nije predaleko
                // addr je zapravo broj instrukcije, tako da se adresa dobija mnozenjem sa 4
                int displacement = (int) (symtab->getAddress(element.first) - addr * 4 - 4);
                if (instructions[addr].first && displacement <= MAX_DISP) {
                    intToHex32b(displacement, hex_num, 4);

                    if (instructions.at(addr).second[0] == 0x21) {
                        instructions.at(addr).second[0] = 0x20;
                    }
                    else {
                        instructions.at(addr).second[0] = instructions.at(addr).second[0] - 8; // JMP, BEQ, BNE, BGT su 0x38 - 0x3b za ucitavanje adrese iz mem i 0x30 - 0x33 za pomeranje pc registra
                    }

                    instructions.at(addr).second[2] |= hex_num[2];
                    instructions.at(addr).second[3] = hex_num[3];
                }
                else {
                    new_vector.push_back(addr);
                }
            }

            if (new_vector.empty()) {
                it = literal_table.erase(it);
            }
            else {
                element.second.clear();
                element.second = new_vector;
                it++;
            }
        }
        else {
            it++;
        }

    }

    l_pool_size = literal_table.size() * 4;

    if (l_pool_size > 0) { // mozda nema ni jedna literalna ili simbolicka konstanta
        l_pool = std::make_unique<LiteralPool>(location_counter, l_pool_size);

        if (!end) {
            // bezuslovni skok za preskok bazena literala
            intToHex32b(l_pool_size, hex_num, 4);

            std::vector<int> new_instruction(4);
            new_instruction[0] = 0x30;
            new_instruction[1] = 0xf0;
            new_instruction[2] = hex_num[2];
            new_instruction[3] = hex_num[3];

            std::pair<bool, std::vector<int>> new_entry;
            new_entry.first = true;
            new_entry.second = new_instruction;

            instructions.push_back(new_entry);
            location_counter += 4;
        }

        for (auto& element: literal_table) {

            bool forwardref;
            is_literal = literalCheck(element.first, value);

            if (!is_literal) {

                value = 0;
                forwardref = true;
                if (symtab->exist(element.first)) {
                    if (symtab->isDefined(element.first)) {
                        addRelocationEntry(relocation_entries, element.first, current_section, location_counter);
                        forwardref = false;
                    }
                }
                else {
                    symtab->addSymbol(element.first, 0, "", false, false, false);
                    symbol_order.push_back(element.first);
                }

                if (forwardref) {
                    symtab->addForwardReference(element.first, current_section, location_counter);
                    if (std::find(bp_symbols.begin(), bp_symbols.end(), element.first) == bp_symbols.end()) {
                        bp_symbols.push_back(element.first);
                    }
                }

            }

            intToHex32b(value, hex_num, 4);

            std::vector<int> new_instruction(4);

            new_instruction[0] = hex_num[3];
            new_instruction[1] = hex_num[2];
            new_instruction[2] = hex_num[1];
            new_instruction[3] = hex_num[0];

            std::pair<bool, std::vector<int>> new_entry;
            new_entry.first = false;
            new_entry.second = new_instruction;

            instructions.push_back(new_entry);

            // Sada se zna gde ce trenutni simbol zavrsiti u bazeny pa se moze odrediti pomeraj od instrukcija koja ga referise

            for (auto addr: element.second) {
                unsigned int displacement = location_counter - addr * 4 - 4;

                intToHex32b(displacement, hex_num, 4);

                instructions.at(addr).second[2] |= hex_num[2];
                instructions.at(addr).second[3] = hex_num[3];

            }

            // Krerati LPEntry i dodati ga u bazen

            std::pair<std::string, unsigned int> lpe;
            lpe.first = element.first;
            lpe.second = location_counter;

            l_pool->values.push_back(lpe);

            location_counter += 4;
        }

        literal_pools.push_back(std::move(l_pool));
        literal_table.clear();
    }

    if (end) {
        symtab->setSectionSize(current_section, location_counter);

        unsigned int num = symtab->getSection(current_section), offset = 0;

        auto* section = new Section(num, location_counter);

        for (auto& instruction: instructions) {
            section->data[offset + 0] = instruction.second[0];
            section->data[offset + 1] = instruction.second[1];
            section->data[offset + 2] = instruction.second[2];
            section->data[offset + 3] = instruction.second[3];
            offset += 4;
        }

        for (auto& lp: literal_pools) {
            section->literal_pools.push_back(std::move(lp));
        }

        for (auto& re: relocation_entries) {
            section->relocation_table.push_back(std::move(re));
        }

        instructions.clear(); // NOTE: ovim se brisu i elementi svakog vektora unutar liste
        literal_pools.clear();
        relocation_entries.clear();

        section_table[current_section] = section;
        section_order.push_back(current_section);

    }

}

void Assembler::createData(bool& reset, unsigned int& critical_address, std::unique_ptr<InstructionParameters>& params) {

    std::vector<int> new_instruction(4);
    bool exist = false;
    int ab, cd, dd, hex_num[8], displacement = 0;
    unsigned int gpr0, gpr1, gpr2;
    std::stringstream ss;
    int op_code = params->op_code;

    bool is_jump = params->op_name == "JMP" || params->op_name == "CALL" || params->op_name == "BEQ" || params->op_name == "BNE" || params->op_name == "BGT";

    if (params->arg_num != params->arg_exp) {
        throw std::logic_error("Wrong number of arguments!\nLine: " + std::to_string(line_num) + " -> " + params->op_name);
    }

    if (!getRegnum(params->reg0, gpr0, params->op_name == "CSRWR" || params->op_name == "IRET")) {
        throw std::logic_error("Register format error!\nLine: " + std::to_string(line_num) + " -> " + params->reg0);
    }
    if (!getRegnum(params->reg1, gpr1, params->op_name == "CSRRD")) {
        throw std::logic_error("Register format error!\nLine: " + std::to_string(line_num) + " -> " + params->reg1);
    }
    if (!getRegnum(params->reg2, gpr2, false)) {
        throw std::logic_error("Register format error!\nLine: " + std::to_string(line_num) + " -> " + params->reg2);
    }

    if (gpr0 > 15 || gpr1 > 15 || gpr2 > 15) {
        throw std::logic_error("Register number out of scope!\nLine: " + std::to_string(line_num));
    }

    if (!params->operand.empty()) {

        if (symtab->isSectionName(params->operand)) {
            throw std::logic_error("Section name can't be used as an operand/label!\nLine: " + std::to_string(line_num) + " -> " + params->operand);
        }

        // AKo se radi o skoku i simbol je vec definisan u istoj sekciji, pomeraj je stalan pa mogu odmah da ga ugradim u instrukciju koja sada dodaje taj pomeraj na pc
        if (is_jump && symtab->isDefined(params->operand) && symtab->getSection(params->operand) == symtab->getSection(current_section) && abs((int) symtab->getAddress(params->operand) - (int) params->jmp_addr) <= MAX_DISP) {
            if (params->op_name == "CALL") {
                op_code = 0x20;
            }
            else {
                op_code = op_code - 8; // JMP, BEQ, BNE, BGT su 0x38 - 0x3b za ucitavanje adrese iz mem i 0x30 - 0x33 za pomeranje pc registra
            }
            displacement = static_cast<int>(symtab->getAddress(params->operand) - params->jmp_addr - 4);
        }
        else {

            // Da li je u prethodnim bazenima iste sekcije i moze da dobaci?
            for (auto& lp: literal_pools) {
                for (auto& lpe: lp->values) {
                    if (lpe.first == params->operand) {
                        if (params->jmp_addr - lpe.second <= MAX_DISP) {
                            exist = true;
                            // [negativan] pomeraj koji ide u instrukciju
                            displacement = (int) (lpe.second - params->jmp_addr);
                            break;
                        }
                    }
                }
            }

            if (!exist) {
                bool found = false;

                for (auto& e: literal_table) {
                    if (e.first == params->operand) {
                        found = true;
                        // jos se ne zna gde ce bazen zavrsiti pa se belezi mesto za prepravku
                        e.second.push_back(instructions.size());
                        break;
                    }
                }

                if (!found) {
                    std::pair<std::string, std::vector<unsigned int>> lt_entry;
                    lt_entry.first = params->operand;
                    lt_entry.second.push_back(instructions.size());
                    literal_table.push_back(lt_entry);

                    if (reset) {
                        critical_address = params->jmp_addr + MAX_DISP;
                        reset = false;
                    }
                }

            }

        }

    }

    if (params->op_name == "POP" || params->op_name == "RET" || params->op_name == "IRET") {
        displacement = 4;
    }
    else if (params->op_name == "PUSH") {
        displacement = -4;
    }

    // kreiranje instrukcije i dodavanje u instructions listu

    ss << std::hex << gpr0 << std::hex << gpr1;
    ss >> ab;
    ss.clear();

    intToHex32b(displacement, hex_num, 8);

    ss << std::hex << gpr2;
    ss << std::hex << hex_num[5];
    ss >> cd;
    ss.clear();

    ss << std::hex << hex_num[6];
    ss << std::hex << hex_num[7];
    ss >> dd;
    ss.clear();

    new_instruction[0] = op_code;
    new_instruction[1] = ab;
    new_instruction[2] = cd;
    new_instruction[3] = dd;

    std::pair<bool, std::vector<int>> new_entry;
    new_entry.first = is_jump;
    new_entry.second = new_instruction;

    instructions.push_back(new_entry);

    location_counter += 4;

    // provera da li smo dosli do kriticne adrese:
    if (!reset && location_counter >= critical_address) {
        createSection(false);
        reset = true;
    }

}

void Assembler::processInputFile() {

    std::fstream fs(input_file, std::ios::in);

    if (!fs.is_open()) {
        throw std::runtime_error("Input file not found!");
    }

    std::regex COMMENT_LINE(R"(^#.*$)");
    std::regex DOTLINE(R"(^([A-Za-z_][A-Za-z0-9_]*\s*\:\s*)?(\.[A-Za-z0-9_]+)(\s*\.?[A-Za-z0-9_\s\,\-]+)?$)");
    std::regex INSLINE(R"(^([A-Za-z_][A-Za-z0-9_]*\s*\:\s*)?([A-Za-z0-9_]+)(\s*\.?[%$A-Za-z0-9_\s\,\-\[\]\+]+)?$)");
    std::regex LABLINE(R"(^[A-Za-z_][A-Za-z0-9_]*\s*\:\s*$)");
    std::smatch match;


    unsigned int critical_addr = 0, jmp_addr;
    bool reset = true;
    std::unique_ptr<InstructionParameters> ins_params;
    bool end_detected = false;

    while (!fs.eof()) {

        line_num++;

        std::string line, temp;
        std::stringstream ss;

        getline(fs, temp);
        trim(temp, "");

        // Obrada i komentara koji nisu na pocetku linije
        ss.str(temp);
        if (temp[0] != '#') {
            getline(ss, line, '#');
        }
        else {
            line = temp;
        }
        ss.clear();
        trim(line, "");


        if (line.empty() || std::regex_match(line, match, COMMENT_LINE)) {
            //std::cout << "Comment found" << std::endl;
        }
        else if (std::regex_match(line, match, DOTLINE)) {
            std::string label = match[1];
            std::string directive = match[2];
            std::string params = match[3];

            /*std::cout << "Dotline found" << std::endl;
            std::cout << "Directive: " << directive << "\n" << std::endl;*/

            std::string section_name;
            std::string symbol_name;
            std::string buffer;
            std::string operand;

            unsigned int value;

            if (!label.empty()) {
                trim(label, ":");

                processLabel(label);
            }

            switch (directiveStringToCode(directive)) {

                case GLOBAL:

                    ss.str(params);

                    while (getline(ss, symbol_name, ',')) {
                        trim(symbol_name, "");
                        if (symtab->exist(symbol_name)) {
                            if (symtab->isExtern(symbol_name)) {
                                throw std::logic_error("Simbol can't be both global and extern!\nLine " + std::to_string(line_num) + " -> " + symbol_name);
                            }
                            symtab->setGlobal(symbol_name);
                        }
                        else {
                            symtab->addSymbol(symbol_name, 0, "", true, false, false);
                            symbol_order.push_back(symbol_name);
                        }
                    }

                    break;

                case EXTERN:

                    ss.str(params);

                    while (getline(ss, symbol_name, ',')) {
                        trim(symbol_name, "");
                        if (!symtab->exist(symbol_name)) {
                            symtab->addSymbol(symbol_name, 0, "", true, true, false);
                            symtab->setDefined(symbol_name);
                            symbol_order.push_back(symbol_name);
                        }
                        else {
                            std::string err_msg = "Line: " + std::to_string(line_num) + " -> " + symbol_name;
                            if (symtab->isExtern(symbol_name)) {
                                throw std::logic_error("Multiple definition of symbol!\n" + err_msg);
                            }
                            else if (symtab->isGlobal(symbol_name)) {
                                throw std::logic_error("Simbol can't be both global and extern!\nLine " + err_msg);
                            }
                            else {
                                throw std::logic_error("Symbol must be set as extern before usage!\n" + err_msg);
                            }

                        }
                    }

                    break;

                case SECTION:

                    section_name = match[3];
                    trim(section_name, "");

                    if (!current_section.empty()) {
                        createSection(true);
                        reset = true;
                    }

                    current_section = section_name;

                    if (!symtab->exist(section_name)) {
                        symtab->addSymbol(section_name, 0, current_section, false, false, true);
                        symtab->setDefined(section_name);
                    }
                    else {
                        if (symtab->isSectionName(section_name)) {
                            throw std::logic_error("Section name can't be use twice!\nLine: " + std::to_string(line_num) + " -> " + section_name);
                        }
                        throw std::logic_error("Section name can't be used as an operand/label!\nLine: " + std::to_string(line_num) + " -> " + section_name);
                    }

                    location_counter = 0;

                    break;

                case WORD:

                    ss.str(params);

                    while(getline(ss, buffer, ',')) {

                        trim(buffer, "");
                        bool is_literal = literalCheck(buffer, value), forwardref = false;

                        if (!is_literal) {

                            value = 0;

                            if (symtab->exist(buffer)) {
                                if (symtab->isDefined(buffer)) {
                                    addRelocationEntry(relocation_entries, buffer, current_section, location_counter);
                                }
                                else {
                                    forwardref = true;
                                }
                            }
                            else {
                                forwardref = true;
                                symtab->addSymbol(buffer, 0, "", false, false, false);
                                symbol_order.push_back(buffer);
                            }

                            if (forwardref) {
                                symtab->addForwardReference(buffer, current_section, location_counter);
                                if (std::find(bp_symbols.begin(), bp_symbols.end(), buffer) == bp_symbols.end()) {
                                    bp_symbols.push_back(buffer);
                                }
                            }

                        }

                        int hex_num[4];
                        std::vector<int> new_instruction(4);

                        intToHex32b(value, hex_num, 4);

                        new_instruction[0] = hex_num[3];
                        new_instruction[1] = hex_num[2];
                        new_instruction[2] = hex_num[1];
                        new_instruction[3] = hex_num[0];

                        std::pair<bool, std::vector<int>> new_entry;
                        new_entry.first = false;
                        new_entry.second = new_instruction;

                        instructions.push_back(new_entry);

                        location_counter += 4;

                        // provera da li smo dosli do kriticne adrese:
                        if (!reset && location_counter >= critical_addr) {
                            createSection(false);
                            reset = true;
                        }

                    }

                    break;

                case SKIP:

                    operand = match[3];
                    trim(operand, "");

                    if (literalCheck(operand, value)) {
                        // RETHINK: Ovde sam ogranicio da broj preskocenih bajtova mora da bude umnozak velicine instrukcije. Da li sam smeo to da uradim?
                        if (value % 4 != 0) {
                            throw std::logic_error("Number of bytes to skip must be multiply of 4!\nLine: " + std::to_string(line_num) + " -> " + operand);
                        }

                        for (int i = 0; i < value / 4; i++) {
                            ins_params = std::make_unique<InstructionParameters>(0x00, "", 1, 1, "%r0", "%r0", "%r0", "", 0);
                            createData(reset, critical_addr, ins_params);
                        }

                    }
                    else {
                        throw std::logic_error("Operand is not a literal!\nLine: " + std::to_string(line_num) + " -> " + operand);
                    }

                    break;

                case END:

                    if (!current_section.empty()) {
                        createSection(true);
                        reset = true;
                    }
                    else {
                        throw std::logic_error("File must have at least one section!\n");
                    }

                    // Kod za backpatching [i kreiranje relsym]

                    for (auto& symbol: bp_symbols) {

                        if (symtab->isDefined(symbol)) {
                            for (auto& bp_entry: symtab->getBPTable(symbol)) {
                                addRelocationEntry(section_table.at(bp_entry->section_name)->relocation_table,symbol, bp_entry->section_name, bp_entry->offset);
                            }
                        }
                        else {
                            throw std::logic_error("Undefined symbol: " + symbol);
                        }
                    }


                    // Ispis prolaza

                    symtab->print();

                    for (auto & section : section_table) {
                        Section* curr = section.second;

                        std::cout << "\nSection number " << curr->number << " : " << section.first << std::endl;
                        for (int i = 0; i < curr->size; i++) {
                            std::cout << std::hex << std::setw(2) << std::setfill('0') << curr->data[i] << " ";
                            if (i % 4 == 3) {
                                std::cout << "\n";
                            }
                        }
                    }

                    std::cout << std::endl;

                    end_detected = true;

                    break;

                case DEFAULT_DIRECTIVE:

                    throw std::logic_error("Unknown directive!\nLine: " + std::to_string(line_num) + " -> " + directive);

            }

        }
        else if (std::regex_match(line, match, INSLINE)) {
            std::string label = match[1];
            std::string instruction = match[2];
            std::string params = match[3];

            std::regex VALUE(R"(^\$([A-Za-z0-9_]*)$)");
            std::regex REGVALUE(R"(^\%[A-Za-z0-9_]*$)");
            std::regex REG_MEMVALUE(R"(^\[(\%[A-Za-z0-9_]*)\s*\]$)");
            std::regex REG_PLUS_LS_MEMVALUE(R"(^\[(\%[A-Za-z0-9_]*)\s*\+\s*([A-Za-z0-9_]+)\]$)");

            std::string operand, r0, r1, r2, r3, temp_reg;
            bool to_pop = false, add_disp = false;
            unsigned int disp = 0;

            // Parsiranje argumenata
            std::vector<std::string> args;

            std::string buffer;
            ss.str(params);
            while (getline(ss, buffer, ',')) {
                trim(buffer, "");
                args.push_back(buffer);
            }

            if (!label.empty()) {
                trim(label, ":");

                processLabel(label);
            }

            switch (instructionStringToCode(instruction)) {

                case HALT:

                    ins_params = std::make_unique<InstructionParameters>(0x00, "HALT", args.size(), 0, "%r0", "%r0", "%r0", "", 0);

                    break;

                case INT:

                    ins_params = std::make_unique<InstructionParameters>(0x10, "INT", args.size(), 0, "%r0", "%r0", "%r0", "", 0);

                    break;

                case IRET:

                    ins_params = std::make_unique<InstructionParameters>(0x93, "POP", 1, 1, "%pc", "%sp", "%r0", "", 0);
                    createData(reset, critical_addr, ins_params);

                    ins_params = std::make_unique<InstructionParameters>(0x93, "IRET", args.size(), 0, "%status", "%sp", "%r0", "", 0);

                    break;

                case CALL:

                    jmp_addr = location_counter;
                    operand = !args.empty() ? args.at(0) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x21, "CALL", args.size(), 1, "%r0", "%r15", "%r0", operand, jmp_addr);


                    break;

                case RET:

                    ins_params = std::make_unique<InstructionParameters>(0x93, "RET", args.size(), 0, "%pc", "%sp", "%r0", "", 0);

                    break;

                case JMP:

                    jmp_addr = location_counter;
                    operand = !args.empty() ? args.at(0) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x38, "JMP", args.size(), 1, "%r15", "%r0", "%r0", operand, jmp_addr);

                    break;

                case BEQ:

                    // Ako korisnik unese manje od 3 argumenta a ja saljem funkciji args[2], dolazi do nedefinisanog ponasanja i zbog toga provera ispod
                    jmp_addr = location_counter;
                    r1 = !args.empty() ? args.at(0) : "";
                    r2 = args.size() > 1 ? args.at(1) : "";
                    operand = args.size() > 2 ? args.at(2) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x39, "BEQ", args.size(), 3, "%r15", r1, r2, operand, jmp_addr);

                    break;

                case BNE:

                    jmp_addr = location_counter;
                    r1 = !args.empty() ? args.at(0) : "";
                    r2 = args.size() > 1 ? args.at(1) : "";
                    operand = args.size() > 2 ? args.at(2) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x3a, "BNE", args.size(), 3, "%r15", r1, r2, operand, jmp_addr);

                    break;

                case BGT:

                    jmp_addr = location_counter;
                    r1 = !args.empty() ? args.at(0) : "";
                    r2 = args.size() > 1 ? args.at(1) : "";
                    operand = args.size() > 2 ? args.at(2) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x3b, "BGT", args.size(), 3, "%r15", r1, r2, operand, jmp_addr);

                    break;

                case PUSH:

                    r2 = !args.empty() ? args.at(0) : "";
                    ins_params = std::make_unique<InstructionParameters>(0x81, "PUSH", args.size(), 1, "%sp", "%r0", r2, "", 0);

                    break;

                case POP:

                    r0 = !args.empty() ? args.at(0) : "";
                    ins_params = std::make_unique<InstructionParameters>(0x93, "POP", args.size(), 1, r0, "%sp", "%r0", "", 0);

                    break;

                case XCHG:

                    r2 = !args.empty() ? args.at(0) : "";
                    r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x40, "XCHG", args.size(), 2, "%r0", r1, r2, "", 0);

                    break;

                case ADD:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x50, "ADD", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case SUB:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x51, "SUB", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case MUL:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x52, "MUL", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case DIV:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x53, "DIV", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case NOT:

                    r0 = r1 = !args.empty() ? args.at(0) : "";
                    ins_params = std::make_unique<InstructionParameters>(0x60, "NOT", args.size(), 1, r0, r1, "%r0", "", 0);

                    break;

                case AND:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x61, "AND", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case OR:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x62, "OR", args.size(), 2, r0, r1, r2, "", 0); //vlado

                    break;

                case XOR:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x63, "XOR", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case SHL:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x70, "SHL", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case SHR:

                    r2 = !args.empty() ? args.at(0) : "";
                    r0 = r1 = args.size() > 1 ? args.at(1) : "";

                    ins_params = std::make_unique<InstructionParameters>(0x71, "SHR", args.size(), 2, r0, r1, r2, "", 0);

                    break;

                case LD:

                    operand = args[0];

                    jmp_addr = location_counter;

                    if (operand.empty() || std::regex_match(operand, match, VALUE)) {
                        operand = match[1];
                        r0 = args.size() > 1 ? args.at(1) : "";
                        ins_params = std::make_unique<InstructionParameters>(0x92, "LD", args.size(), 2, r0, "%pc", "%r0", operand, jmp_addr);
                    }
                    else if (std::regex_match(operand, match, REGVALUE)) {
                        r0 = args.size() > 1 ? args.at(1) : "";
                        r1 = match[0];
                        ins_params = std::make_unique<InstructionParameters>(0x91, "LD", args.size(), 2, r0, r1, "%r0", "", jmp_addr);
                    }
                    else if (std::regex_match(operand, match, REG_MEMVALUE)) {
                        r0 = args.size() > 1 ? args.at(1) : "";
                        r1 = match[1];
                        ins_params = std::make_unique<InstructionParameters>(0x92, "LD", args.size(), 2, r0, r1, "%r0", "", jmp_addr);
                    }
                    else if (std::regex_match(operand, match, REG_PLUS_LS_MEMVALUE)) {

                        std::string reg = match[1];
                        std::string symbol = match[2];
                        unsigned int value;

                        //Ukoliko vrednost literala nije moguće zapisati na širini od 12 bita kao označenu vrednost prijaviti grešku u procesu asembliranja.
                        /*Ukoliko konačna vrednost simbola nije poznata u trenutku asembliranja ili konačnu vrednost simbola nije moguće zapisati na širini
                         od 12 bita kao označenu vrednost prijaviti grešku u procesu asembliranja.*/

                        if (literalCheck(symbol, value)) {
                            if (value > MAX_DISP) {
                                throw std::logic_error("Numeric literal value bigger than signed 12bits!\nLine" + std::to_string(line_num) + " -> " + symbol);
                            }
                        }
                        else {
                            // Posto nemam .equ, vrednost simbola sigurno nece biti poznata u toku asembliranja
                            throw std::logic_error("Symbol final value unknown!\nLine" + std::to_string(line_num) + " -> " + symbol);
                        }

                        // literal ne mora u bezen jer je sigurno <= 12b, pa moze da stane u instrukciju
                        ins_params = std::make_unique<InstructionParameters>(0x92, "LD", args.size(), 2, args[1], reg, "%r0", "", 0);

                        // naknadno treba da se doda DDDD DDDDDDDD u instrukciju
                        add_disp = true;
                        disp = value;


                    }
                    else {
                        temp_reg = args.at(1) == "%r1" ? "%r2" : "%r1";

                        // push %r1
                        ins_params = std::make_unique<InstructionParameters>(0x81, "PUSH", 1, 1, "%sp", "%r0", temp_reg, "", 0);
                        createData(reset, critical_addr, ins_params);

                        // ld %r1, [operand_addr] - operand ce biti u bazenu literala
                        ins_params = std::make_unique<InstructionParameters>(0x92, "LD", 1, 1, temp_reg, "%pc", "%r0", operand, location_counter);
                        createData(reset, critical_addr, ins_params);

                        // ld %reg, [%r1]
                        r0 = args.size() > 1 ? args.at(1) : "";

                        ins_params = std::make_unique<InstructionParameters>(0x92, "LD", args.size(), 2, r0, temp_reg, "%r0", "", 0);
                        //createData(reset, critical_addr, ins_params);
                        to_pop = true;

                        // pop %r1
                        // ins_params = std::make_unique<InstructionParameters>(0x93, "POP", 1, 1, temp_reg, "%sp", "%r0", operand, 0);

                    }

                    break;

                case ST:

                    operand = args.size() > 1 ? args.at(1) : "";

                    jmp_addr = location_counter;

                    if (operand.empty() || std::regex_match(operand, match, VALUE)) {

                        operand = match[1];
                        r2 = args.at(0);
                        ins_params = std::make_unique<InstructionParameters>(0x80, "ST", args.size(), 2, "%pc", "%r0", r2, operand, jmp_addr);

                    }
                    else if (std::regex_match(operand, match, REGVALUE)) {
                        r0 = args.at(1);
                        r1 = args.at(0);
                        ins_params = std::make_unique<InstructionParameters>(0x91, "ST", args.size(), 2, r0, r1, "%r0", "", 0);
                    }
                    else if (std::regex_match(operand, match, REG_MEMVALUE)) {
                        r0 = match[1];
                        r2 = args.at(0);
                        ins_params = std::make_unique<InstructionParameters>(0x80, "ST", args.size(), 2, r0, "%r0", r2, "", 0);
                    }
                    else if (std::regex_match(operand, match, REG_PLUS_LS_MEMVALUE)) {

                        std::string reg = match[1];
                        std::string symbol = match[2];
                        unsigned int value;

                        //Ukoliko vrednost literala nije moguće zapisati na širini od 12 bita kao označenu vrednost prijaviti grešku u procesu asembliranja.
                        /*Ukoliko konačna vrednost simbola nije poznata u trenutku asembliranja ili konačnu vrednost simbola nije moguće zapisati na širini
                         od 12 bita kao označenu vrednost prijaviti grešku u procesu asembliranja.*/

                        if (literalCheck(symbol, value)) {
                            if (value > MAX_DISP) {
                                throw std::logic_error("Numeric literal value bigger than signed 12bits!\nLine" + std::to_string(line_num) + " -> " + symbol);
                            }
                        }
                        else {
                            // Posto nemam .equ, vrednost simbola sigurno nece biti poznata u toku asembliranja
                            throw std::logic_error("Symbol final value unknown!\nLine" + std::to_string(line_num) + " -> " + symbol);
                        }

                        r2 = args.at(0);
                        ins_params = std::make_unique<InstructionParameters>(0x80, "ST", args.size(), 2, reg, "%r0", r2, "", 0);

                        // naknadno treba da se doda DDDD DDDDDDDD u instrukciju
                        add_disp = true;
                        disp = value;
                    }
                    else {

                        r2 = args.at(0);
                        ins_params = std::make_unique<InstructionParameters>(0x82, "ST", args.size(), 2, "%pc", "%r0", r2, operand, jmp_addr);

                    }

                    break;

                case CSRRD:

                    r1 = !args.empty() ? args.at(0) : "";
                    r0 = args.size() > 1 ? args.at(1) : "";
                    ins_params = std::make_unique<InstructionParameters>(0x90, "CSRRD", args.size(), 2, r0, r1, "%r0", "", 0);

                    break;

                case CSRWR:

                    r1 = !args.empty() ? args.at(0) : "";
                    r0 = args.size() > 1 ? args.at(1) : "";
                    ins_params = std::make_unique<InstructionParameters>(0x94, "CSRWR", args.size(), 2, r0, r1, "%r0", "", 0);

                    break;

                case DEFAULT_INSTRUCTION:

                    throw std::logic_error("Unknown instruction!\nLine: " + std::to_string(line_num) + " -> " + instruction);

            }

            args.clear();

            createData(reset, critical_addr, ins_params);

            // Za LD i ST tip 4 ostalo je da se pop-uje korisceni registar
            if (to_pop) {
                ins_params = std::make_unique<InstructionParameters>(0x93, "POP", 1, 1, temp_reg, "%sp", "%r0", "", 0);
                createData(reset, critical_addr, ins_params);
            }

            // Za LD i ST tip 3 ostalo je da se doda pomeraj (na poslednje kreiranu instrukciju)
            if (add_disp) {
                int hex_num[4];
                std::vector<int> new_instruction(4);

                intToHex32b(disp, hex_num, 4);

                instructions.back().second[2] = hex_num[2];
                instructions.back().second[3] = hex_num[3];
            }

        }
        else if (std::regex_match(line, match, LABLINE)) {
            std::string label = match[0];

            //std::cout << "Labline found: " << label << std::endl;

            if (!label.empty()) {
                trim(label, ":");

                processLabel(label);
            }
        }
        else {
            throw std::logic_error("Invalid syntax at line: " + std::to_string(line_num));
        }

        if (end_detected) {
            break;
        }

    }

    if (!end_detected) {
        throw std::logic_error("There is no .end directive!\n");
    }

}


void Assembler::addRelocationEntry(std::list<std::unique_ptr<RelocationEntry>>& rel_table, std::string& symbol_name, std::string& section_name, unsigned int offset) {

    int addend = 0;
    std::string nm;

    if (symtab->isGlobal(symbol_name)) {
        nm = symbol_name;
    }
    else {
        addend = (int) symtab->getAddress(symbol_name);

        nm = symtab->getSectionName(symbol_name);
    }

    std::unique_ptr<RelocationEntry> re = std::make_unique<RelocationEntry>(R_X86_64_32, offset, nm, addend);
    rel_table.push_back(std::move(re));

}

void Assembler::createOutputFile() {

    std::string filename = output_file;
    std::fstream ofs(filename, std::ios::out);

    int count = 0, sz = (int) section_order.size();
    std::string type, ndx, bind;

    //output_file.erase(output_file.length() - 2);

    // Zaglavlje

    // Tabela simbola
    ofs << "#.symtab " << symbol_order.size() + section_order.size() << std::endl;

    for (int i = 0; i < sz; i++) {
        std::string section = section_order.back();
        symbol_order.push_front(section);
        section_order.pop_back();
        section_order.push_front(section);
    }
    for (const auto& s: symbol_order) {
        ofs << std::dec << ++count << ":  ";
        ofs << std::hex << std::setw(8) << std::setfill('0') << symtab->getAddress(s) << "  ";

        type = count <= sz ? "SCTN" : "NOTYP";
        ofs << std::setw(5) << std::setfill(' ') << type << "  ";

        bind = symtab->isGlobal(s) ? "GLOB" : "LOC";
        ofs << std::setw(4) << std::setfill(' ') << bind << "  ";

        unsigned int sec = symtab->getSection(s);
        if (sec != 0) {
            int num = 0;
            for (auto& sctn: section_order) {
                num++;
                if (symtab->getSection(sctn) == sec) {
                    ndx = std::to_string(num);
                    break;
                }
            }
        }
        else {
            ndx = "UND";
        }
        ofs << std::setw(3) << std::setfill(' ') << ndx << "  ";
        ofs << s << std::endl;
    }

    ofs << std::endl;

    // TO DO: Izmena ispisa tako da bude u skladu sa little endian a ne big endian
    // Mogu da izmenim ovde a u ranijem kodu ne menjam bilo sta (?) ili da ovde ne menjam bilo sta a izmenim raniji kod

    //Sekcije:
    for (auto& item: section_table) {
        ofs << "#" << item.first << " " << std::dec << item.second->size << std::endl;
        for (int i = 0; i < item.second->size; i++) {
            ofs << std::hex << std::setw(2) << std::setfill('0') << item.second->data[i] << " ";
            if (i % 4 == 3) {
                ofs << "\n";
            }
        }
    }

    ofs << std::endl;

    //Relokacioni zapisi
    for (auto& item: section_table) {
        if (!item.second->relocation_table.empty()) {
            ofs << "#rela" << item.first << " " << item.second->relocation_table.size() << std::endl;
            for (auto& rel_entry: item.second->relocation_table) {
                ofs << std::hex << std::setw(8) << std::setfill('0') << rel_entry->offset << " ";
                ofs << (rel_entry->type == R_X86_64_PC32 ? "R_X86_64_PC32" : "R_XB6_64_32") << " ";
                ofs << rel_entry->symbol << " ";
                ofs << rel_entry->addend << std::endl;
            }
        }
    }

}
