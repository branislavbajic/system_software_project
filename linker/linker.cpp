#include <iostream>
#include <fstream>
#include <iomanip>
#include <algorithm>
#include <sstream>

#include "linker.h"

Linker::Linker(const std::string& output_file, std::list<std::string> input_files, std::list<std::pair<std::string, unsigned int>> section_places) {

    this->output_file = output_file;
    this->input_files = std::move(input_files);
    this->section_places = std::move(section_places);
    this->output_file_size = 0;

    // ubacivanje sekcija za koje postoji -place direktiva na pocetak section_order
    // sortirano po adresi za smestanje da bi se redom tako obradjivale
    for (auto& sp: this->section_places) {
        std::pair<std::string, unsigned int> elem;
        elem.first = sp.first;
        elem.second = 0;
        section_order.push_back(elem);
    }

}

Linker::~Linker()=default;

void Linker::trim(std::string& line, const std::string& additional) {
    while(!line.empty() && (isspace(line[0]) || additional.find(line[0]) != std::string::npos)) {
        line.erase(0,1);
    }
    while(!line.empty() && (isspace(line[line.length() - 1]) || additional.find(line[line.length() - 1]) != std::string::npos)) {
        line.erase(line.length() - 1,1);
    }
}

void Linker::symbolResolution() {

    std::unique_ptr<File> file;
    std::unique_ptr<Section> section;
    std::unique_ptr<Symbol> symbol;
    std::unique_ptr<RelocationEntry> re;
    std::string temp, type, bind, section_num, symbol_name, section_name;
    unsigned int number_of_symbols, number_of_sections, address, size, re_number;
    int byte, addend;

    std::unordered_map<std::string, std::unique_ptr<Symbol>> U, D;
    std::unordered_map<std::string, unsigned int> section_numbers;


    for (auto& filename: input_files) {

        std::fstream ifs(filename, std::ios::in);

        if (!ifs.is_open()) {
            throw std::runtime_error("Input file not found: " + filename);
        }

        if (std::find(file_order.begin(), file_order.end(), filename) != file_order.end()) {
            throw std::logic_error("Multiple files with same name: " + filename);
        }

        file_order.push_back(filename);

        file = std::make_unique<File>(filename);

        ifs >> temp; // #symtab
        ifs >> number_of_symbols;

        number_of_sections = 0;

        // citanje i razresivanje simbola
        for (int i = 0; i < number_of_symbols; i++) {
            ifs >> temp; // redni broj
            ifs >> std::hex >> address >> type >> bind >> section_num >> symbol_name;

            // RETHINK: Da li treba da trimujem procitane vrednosti?
            if (type == "SCTN") {

                //file->section_numbers[symbol_name] = stoi(section_num);
                section_numbers[symbol_name] = stoi(section_num);

                bool found = false;
                for (auto& sctn: section_order) {
                    if (sctn.first == symbol_name) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    std::pair<std::string, unsigned int> elem;
                    elem.first = symbol_name;
                    elem.second = 0;
                    section_order.push_back(elem);
                }
                number_of_sections++;
            }

            int snum;
            if (section_num == "UND") {
                snum = 0;
            }
            else {
                snum = std::stoi(section_num);
            }

            if (bind  == "GLOB") {

                symbol = std::make_unique<Symbol>(symbol_name, address, snum, filename);

                if (section_num != "UND") {
                    if (D.find(symbol_name) != D.end()) {
                        throw std::logic_error("Multiple definition of symbol: " + symbol_name);
                    }
                    if (U.find(symbol_name) != U.end()) {
                        U.erase(symbol_name);
                    }
                    D[symbol_name] = std::move(symbol);
                }
                else {
                    if (D.find(symbol_name) == D.end()) {
                        U[symbol_name] = std::move(symbol);
                    }
                }
            }

        }

        // citanje sekcija
        getline(ifs, temp); // prazan red
        for (int i = 0; i < number_of_sections; i++) {
            ifs >> section_name >> std::dec >> size;
            trim(section_name, "#");

            for (auto& sctn: section_order) {
                if (sctn.first == section_name) {
                    sctn.second += size;
                }
            }

            section = std::make_unique<Section>(section_name, size, section_numbers.at(section_name));
            file->sections[section_name] = std::move(section);

            for (int j = 0; j < size; j++) {
                ifs >> std::hex >> byte;
                file->sections[section_name]->data[j] = byte;
            }

            output_file_size += size;
        }

        section_name.clear();

        // citanje relokacionih zapisa
        getline(ifs, temp); //prazan red
        for (int i = 0; i < number_of_sections; i++) {
            ifs >> section_name; //sekcija relokacionih zapisa
            ifs >> std::hex >> re_number;

            if (section_name.empty()) break; // Nema relokacionih zapisa za sve sekcije

            section_name.erase(0, 5); // Uklanjanje #rela

            for (int j = 0; j < re_number; j++) {
                ifs >> std::hex >> address;
                ifs >> type;
                ifs >> symbol_name;
                ifs >> std::hex >> addend;

                unsigned int sec_num = section_numbers.at(section_name);

                re = std::make_unique<RelocationEntry>(section_name, sec_num, address, type == "R_XB6_64_32", symbol_name, addend);

                file->relocation_entries.push_back(std::move(re));
            }

            section_name.clear();
        }

        section_numbers.clear();

        files[filename] = std::move(file);

    }

    if (!U.empty()) {
        throw std::logic_error("Symbol undefined: " + U.begin()->first);
    }
    else {
        symtab.swap(D);
    }

}

void Linker::relocation() {

    std::unique_ptr<File> combined_file = std::make_unique<File>(output_file);
    unsigned int first_available_address = 0, local_address, section_counter = 1;

    // Spajanje sekcija istog tipa uz obradu -place direktiva i kreiranje mape preslikavanja
    for (auto& section: section_order) {

        std::string section_name = section.first;
        unsigned int section_size = section.second;

        std::unique_ptr<Section> combined_section = std::make_unique<Section>(section_name, section_size, section_counter++);

        // Odredjivanje startne adrese (vrednost iz -place direktive ili prva nakon najvece zauzete)
        unsigned int start_address;
        bool found = false;

        for (auto& elem: section_places) {
            if (elem.first == section_name) {
                found = true;
                start_address = elem.second;
                break;
            }
        }

        if (!found) {
            start_address = first_available_address;
        }

        if (start_address < first_available_address) {
            std::string error_msg, addr, available_addr;
            std::stringstream ss_error;

            ss_error << std::hex << std::setw(8) << std::setfill('0') << start_address;
            ss_error >> addr;
            ss_error.clear();

            ss_error << std::hex << std::setw(8) << std::setfill('0') << first_available_address - 1;
            ss_error >> available_addr;
            ss_error.clear();

            error_msg += "Section overlap due to -place directives!\n";
            error_msg += "Section " + section_name;
            error_msg += " starts at address " + addr;
            error_msg += " but previous section ends at " + available_addr;

            throw std::logic_error(error_msg);
        }

        combined_section->address = start_address;
        first_available_address = start_address + section_size;

        local_address = 0;
        for (auto& filename: file_order) {

            if (files.at(filename)->sections.find(section_name) != files.at(filename)->sections.end()) {

                // kreiranje ulaza u tabeli preslikavanja
                unsigned int old_address = files.at(filename)->sections.at(section_name)->address;
                unsigned int new_address = start_address + local_address;

                std::unique_ptr<RelocationMapEntry> rme = std::make_unique<RelocationMapEntry>(section_name, filename, old_address, new_address);

                std::string key = filename + std::to_string(files.at(filename)->sections.at(section_name)->section_number);

                relocation_map[key] = std::move(rme);

                // kopiranje sadrzaja sekcije u zbirnu izlaznu
                for (int i = 0; i < files.at(filename)->sections.at(section_name)->size; i++) {
                    combined_section->data[local_address++] = files.at(filename)->sections.at(section_name)->data[i];
                }
            }

        }

        combined_file->sections[section_name] = std::move(combined_section);

    }

    // Relokacija tabele simbola i dodavanje ulaza za sekcije (one su lokalni simboli u ulaznim fajlovima pa ih nisam ranije dodao)
    for (auto& symbol: symtab) {

        std::string symbol_name = symbol.first;
        unsigned int old_address = symbol.second->address;
        unsigned int old_section_number = symbol.second->section;
        std::string filename = symbol.second->filename;

        std::string key = filename + std::to_string(old_section_number);

        unsigned int new_address = relocation_map.at(key)->new_address + old_address;
        unsigned int new_section_number = combined_file->sections.at(relocation_map.at(key)->section_name)->section_number;

        symbol.second->section = new_section_number;
        symbol.second->address = new_address;

    }

    for (auto& s: combined_file->sections) {
        std::unique_ptr<Symbol> section_symbol = std::make_unique<Symbol>(s.first, s.second->address, combined_file->sections.at(s.first)->section_number, output_file);
        symtab[s.first] = std::move(section_symbol);
    }

    // Razresavanje relokacionih zapisa
    for (auto& filename: file_order) {

        for (auto& rel_entry: files.at(filename)->relocation_entries) {

            // Koliko je sekcija iz ulaznog fajla pomerana u zbirnoj istoimenoj sekciji
            std::string key = filename + std::to_string(rel_entry->section_number);
            unsigned int patch_section_offset = relocation_map.at(key)->new_address - combined_file->sections.at(rel_entry->section)->address;

            int value = (int) symtab.at(rel_entry->symbol_name)->address + rel_entry->addend;

            // Ako je ime simbola u zapisu naziv sekcije, onda se radilo o lokalnom simbolu pa moram da dodam offset jer sekcija mozda vise nije na pocetku zbirne
            if (files.at(filename)->sections.find(rel_entry->symbol_name) != files.at(filename)->sections.end()) {

                // Treba mi koliko se sekcija u kojoj je lokalni simbol bio pomerila
                unsigned int target_section_num = files.at(filename)->sections.at(rel_entry->symbol_name)->section_number;
                key = filename + std::to_string(target_section_num);
                unsigned int target_section_offset = relocation_map.at(key)->new_address - combined_file->sections.at(rel_entry->symbol_name)->address;
                value += (int) target_section_offset;

            }

            if (rel_entry->absolute) {
                int hex_num[4];
                std::stringstream ss1;
                std::string s;
                int num, increment = 2;

                ss1 << std::hex << std::setw(8) << std::setfill('0') << value;
                ss1 >> s;

                for (int i = 0; i < 4; i++) {
                    std::stringstream ss2;
                    std::string temp = s.substr(i * increment, increment);
                    ss2 << temp;
                    ss2 >> std::hex >> num;
                    hex_num[i] = num;
                }

                unsigned int patch_addr = rel_entry->address + patch_section_offset;

                combined_file->sections.at(rel_entry->section)->data[patch_addr + 0] = hex_num[3];
                combined_file->sections.at(rel_entry->section)->data[patch_addr + 1] = hex_num[2];
                combined_file->sections.at(rel_entry->section)->data[patch_addr + 2] = hex_num[1];
                combined_file->sections.at(rel_entry->section)->data[patch_addr + 3] = hex_num[0];
            }
            else {
                // Formula za PC32 je drugacija, ali sigurno necu imati takve zapise pa da ne gubim vreme
            }

        }

    }

    files[output_file] = std::move(combined_file);

}


void Linker::createOutputFile() {

    std::cout << "\nRelocation Map:" << std::endl;
    for (auto& rm_entry : relocation_map) {
        std::cout << rm_entry.second->section_name << " from " << rm_entry.second->filename << "\t" << rm_entry.second->old_address << " --> " << std::hex << rm_entry.second->new_address << std::endl;
    }

    std::cout << "\nOutput data:" << std::endl;
    std::unique_ptr<File> combined_file = std::move(files.at(output_file));

    for (auto& output_section : combined_file->sections) {
        std::cout << "#" << output_section.first << " " << std::hex << std::setw(8) << std::setfill('0') << symtab.at(output_section.first)->address << std::endl;
        for (int i = 0; i < output_section.second->size; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << output_section.second->data[i] << " ";
            if (i % 4 == 3) {
                std::cout << "\n";
            }
        }
    }

    std::cout << "\nOutput table:" << std::endl;
    for (auto& symbol : symtab) {

        std::cout << symbol.first << " " << std::hex << symbol.second->address << " " << std::dec << symbol.second->section << std::endl;

    }

    std::string filename = output_file;
    std::fstream ofs(filename, std::ios::out);


    for (auto& section: section_order) {

        // TO DO: Slaganje sekcija ako idu odmah jedna nakon druge
        // AKo se prethodna zavrsava na adresi koja nije deljiva sa 8, nastaviti narednu u istom redu, a ne u sledecem

        std::string section_name = section.first;
        unsigned int start_address = combined_file->sections.at(section_name)->address;
        unsigned int size = combined_file->sections.at(section_name)->size;

        unsigned int total = 0;


        while (total < size) {
            ofs << std::hex << std::setw(8) << std::setfill('0') << start_address + total << ": ";

            int i = 0;
            while (total + i < size && i < 8) {
                ofs << std::hex << std::setw(2) << std::setfill('0') << combined_file->sections.at(section_name)->data[total + i] << " ";
                i++;
            }

            if (i == 8 || total + i == size) {
                ofs << std::endl;
            }

            total += 8;
        }

    }

}

