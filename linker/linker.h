#ifndef LINKER_H
#define LINKER_H

#include <fstream>
#include <string>
#include <list>
#include <map>
#include <unordered_map>
#include <memory>

class Linker {

    public:
        Linker(const std::string&, std::list<std::string>, std::list<std::pair<std::string, unsigned int>>);
        ~Linker();

        void symbolResolution();
        void relocation();
        void createOutputFile();

        static void trim(std::string&, const std::string&);

    private:
        std::string output_file, err_value;
        std::list<std::string> input_files;
        std::list<std::pair<std::string, unsigned int>> section_places;
        unsigned int output_file_size;

        struct Symbol {
            std::string name;
            unsigned int address;
            unsigned int section;
            std::string filename;

            Symbol(const std::string& nm, unsigned int addr, unsigned int snum, const std::string& fn) {
                name = nm;
                address = addr;
                section = snum;
                filename = fn;
            }
        };

        struct Section {

            std::string name;
            unsigned int address;
            unsigned int size;
            unsigned int section_number;
            std::unique_ptr<int[]> data;

            Section(const std::string& nm, unsigned int sz, unsigned int sec_num) {
                name = nm;
                address = 0;
                size = sz;
                section_number = sec_num;

                data = std::make_unique<int[]>(sz);
            }

        };

        struct RelocationEntry {

            std::string section;
            unsigned int section_number;
            unsigned int address;
            bool absolute;
            std::string symbol_name;
            int addend;

            RelocationEntry(const std::string& s, unsigned int sn, unsigned int a, bool abs, const std::string& nm, int add) {
                section = s;
                section_number = sn;
                address = a;
                absolute = abs;
                symbol_name = nm;
                addend = add;
            }

        };

        struct File {

            std::string name;
            //std::unordered_map<std::string, std::unique_ptr<Symbol>> symbols;
            std::unordered_map<std::string, std::unique_ptr<Section>> sections;
            //std::unordered_map<std::string, unsigned int> section_numbers;
            std::list<std::unique_ptr<RelocationEntry>> relocation_entries;

            explicit File(const std::string& nm) {
                name = nm;
            }

        };


        struct RelocationMapEntry {

            std::string section_name;
            std::string filename;
            unsigned int old_address;
            unsigned int new_address;

            RelocationMapEntry(const std::string& sn, const std::string& fn, unsigned int oa, unsigned na) {
                section_name = sn;
                filename = fn;
                old_address = oa;
                new_address = na;
            }

        };

        std::unordered_map<std::string, std::unique_ptr<File>> files;
        std::unordered_map<std::string, std::unique_ptr<Symbol>> symtab;
        std::list<std::string> file_order;
        std::list<std::pair<std::string, unsigned int>> section_order;

        std::unordered_map<std::string, std::unique_ptr<RelocationMapEntry>> relocation_map;

};

#endif // LINKER_H