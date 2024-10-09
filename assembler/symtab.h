#ifndef SINGLE_PASS_ASSEMBLER_SYMTAB_H
#define SINGLE_PASS_ASSEMBLER_SYMTAB_H

#include <iostream>
#include <unordered_map>
#include <list>
#include <memory>

struct BPTableEntry {
    std::string section_name;
    unsigned int offset;
};

class SymTab {

    public:
        SymTab();
        ~SymTab();

        void addSymbol(const std::string&, unsigned int, const std::string&, bool, bool, bool);
        bool exist(const std::string&) const;
        unsigned int getAddress(const std::string&) const;
        unsigned int getSection(const std::string&) const;
        std::string getSectionName(const std::string&) const;
        bool isGlobal(const std::string&) const;
        bool isExtern(const std::string&) const;
        bool isSectionName(const std::string&) const;
        void setAddress(const std::string&, unsigned int);
        void setSection(const std::string&, const std::string&);
        void setSectionSize(const std::string&, unsigned int);
        void setGlobal(const std::string&);

        // za backpatching
        bool isDefined(const std::string&) const;
        void setDefined(const std::string&);
        void addForwardReference(const std::string&, const std::string&, unsigned int);
        std::list<std::unique_ptr<BPTableEntry>> getBPTable(const std::string&);

        void print() const;

    private:
        static unsigned int NUM;

        struct Symbol {
            unsigned int num;
            std::string name;
            unsigned int address;
            unsigned int section;
            bool global;
            bool is_extern;
            bool is_section_name;
            unsigned int section_size;

            // Single pass exclusive
            bool defined;
            std::list<std::unique_ptr<BPTableEntry>> bp_table;

            Symbol (unsigned int n, const std::string& nm, unsigned int addr, unsigned int sec, bool glb, bool is_ext, bool isn, unsigned int sz) {
                num = n;
                name = nm;
                address = addr;
                section = sec;
                global = glb;
                is_extern = is_ext;
                is_section_name = isn;
                section_size = sz;
                defined = false;
            }

        };

        std::unordered_map<std::string, Symbol*> table;
        std::list<std::string> symbol_order;

};

#endif //SINGLE_PASS_ASSEMBLER_SYMTAB_H
