#include "symtab.h"

unsigned int SymTab::NUM = 0;

SymTab::SymTab() = default;

SymTab::~SymTab() {

    for (auto& symbol: symbol_order) {
        Symbol* temp = table.at(symbol);
        delete temp;
    }

    symbol_order.clear();
    table.clear();

}

void SymTab::addSymbol(const std::string& name, unsigned int address, const std::string& section, bool global, bool ext, bool isn) {

    unsigned int number = ++NUM;
    unsigned int section_number;
    Symbol* symbol;

    if (section.empty()) {
        section_number = 0;
    }
    else if (table.find(section) == table.end()) {
        section_number = number;
    }
    else {
        section_number = table[section]->num;
    }

    symbol = new Symbol(number, name, address, section_number, global, ext, isn, 0);

    table[name] = symbol;

    symbol_order.push_back(name);

}

bool SymTab::exist(const std::string& name) const {

    if (table.find(name) != table.end()) {
        return true;
    }
    else {
        return false;
    }

}

unsigned int SymTab::getAddress(const std::string& name) const {

    if (!exist(name)) {
        return -1;
    }

    return table.at(name)->address;

}

unsigned int SymTab::getSection(const std::string& name) const {

    if (!exist(name)) {
        return -1;
    }

    return table.at(name)->section;

}

std::string SymTab::getSectionName(const std::string& name) const {

    if (exist(name)) {
        unsigned int section_number = table.at(name)->section;
        for (auto& elem: table) {
            if (elem.second->num == section_number && elem.second->is_section_name) {
                return elem.first;
            }
        }
    }

    return "";

}

bool SymTab::isGlobal(const std::string& name) const {

    if (!exist(name)) {
        return false;
    }

    return table.at(name)->global;

}

bool SymTab::isExtern(const std::string& name) const {

    if (!exist(name)) {
        return false;
    }

    return table.at(name)->is_extern;

}

bool SymTab::isDefined(const std::string& name) const {

    if (!exist(name)) {
        return false;
    }

    return table.at(name)->defined;
}

bool SymTab::isSectionName(const std::string& name) const {

    if (!exist(name)) {
        return false;
    }

    return table.at(name)->is_section_name;
}

void SymTab::setAddress(const std::string& name, unsigned int address) {

    if (table.find(name) != table.end()) {
        table.at(name)->address = address;
    }

}

void SymTab::setSection(const std::string& name, const std::string& section) {

    unsigned int section_number = 0;

    if (table.find(name) != table.end()) {

        if (!section.empty()) {
            section_number = table.at(section)->num;
        }

        table.at(name)->section = section_number;
    }

}

void SymTab::setSectionSize(const std::string& name, unsigned int section_size) {

    if (table.find(name) != table.end()) {
        table.at(name)->section_size = section_size;
    }

}

void SymTab::setGlobal(const std::string& name) {

    if (table.find(name) != table.end()) {
        table.at(name)->global = true;
    }

}


void SymTab::setDefined(const std::string& name) {

    if (table.find(name) != table.end()) {
        table.at(name)->defined = true;
    }

}

void SymTab::addForwardReference(const std::string& symbol, const std::string& section_name, unsigned int offset) {

    std::unique_ptr<BPTableEntry> ptr = std::make_unique<BPTableEntry>();
    ptr->section_name = section_name;
    ptr->offset = offset;

    table.at(symbol)->bp_table.push_back(std::move(ptr));

}

std::list<std::unique_ptr<BPTableEntry>> SymTab::getBPTable(const std::string& name) {

    if (!exist(name)) {
        return {};
    }

    return std::move(table.at(name)->bp_table);

}

void SymTab::print() const {

    if (table.empty()) {
        std::cout << "\nSymbol table is empty!" << std::endl;
    }
    else {
        std::cout << "\nSymbol table: " << std::endl;
        //cout << "Broj\t\t\tNaziv\t\t\tAdresa\t\t\tSekcija\t\t\tGlobal\t\t\tIs_Section\t\t\tVelicina" << endl;
        for (auto& symbol: symbol_order) {
            Symbol* temp = table.at(symbol);
            std::cout << temp->num << " " << symbol << "  Address: " << std::hex << temp->address << "  Section: " << std::dec << temp->section << "  Global: " << (temp->global ? "True" : "False") << "  Extern: " << (temp->is_extern ? "True" : "False") << "  Is_Section: " << (temp->is_section_name ? "True" : "False") << "  Size: " << temp->section_size << std::endl;
        }
        std::cout << std::endl;
    }

}
