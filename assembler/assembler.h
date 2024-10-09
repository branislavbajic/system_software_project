#ifndef SINGLE_PASS_ASSEMBLER_H
#define SINGLE_PASS_ASSEMBLER_H

#include <iostream>
#include <list>
#include <vector>
#include <unordered_map>
#include <utility>
#include <memory>

#include "symtab.h"


enum directive {
    GLOBAL,
    EXTERN,
    SECTION,
    WORD,
    SKIP,
    END,
    DEFAULT_DIRECTIVE
};

enum instruction {
    HALT,
    INT,
    IRET,
    CALL,
    RET,
    JMP,
    BEQ,
    BNE,
    BGT,
    PUSH,
    POP,
    XCHG,
    ADD,
    SUB,
    MUL,
    DIV,
    NOT,
    AND,
    OR,
    XOR,
    SHL,
    SHR,
    LD,
    ST,
    CSRRD,
    CSRWR,
    DEFAULT_INSTRUCTION
};

enum RelocationType {
    R_X86_64_32,
    R_X86_64_PC32
};

class Assembler {

    public:
        Assembler(std::string, std::string);
        ~Assembler();

        void processInputFile();
        void createOutputFile();

        static void trim(std::string&, const std::string&);
        static directive directiveStringToCode(const std::string&);
        static instruction instructionStringToCode(const std::string&);
        static void intToHex32b(unsigned int, int*, int);
        static bool literalCheck(const std::string&, unsigned int&);
        static bool getRegnum(const std::string&, unsigned int&, bool);

    private:
        // Pomocne strukture
        struct InstructionParameters {
            int op_code;
            std::string op_name;
            int arg_num;
            int arg_exp;
            std::string reg0;
            std::string reg1;
            std::string reg2;
            std::string operand;
            unsigned int jmp_addr;

            InstructionParameters(int oc, const std::string& on, int an, int ae, const std::string& r0, const std::string& r1, const std::string& r2, const std::string& op, unsigned int ja) {
                op_code = oc;
                op_name = on;
                arg_num = an;
                arg_exp = ae;
                reg0 = r0;
                reg1 = r1;
                reg2 = r2;
                operand = op;
                jmp_addr = ja;
            }
        };

        struct LiteralPool {

            unsigned int start;
            unsigned int size;
            std::list<std::pair<std::string, unsigned int>> values;

            LiteralPool(unsigned int st, unsigned int sz) {
                start = st;
                size = sz;
            }

        };

        struct RelocationEntry {

            RelocationType type;
            unsigned int offset;
            std::string symbol;
            int addend;

            RelocationEntry(RelocationType rt, unsigned int off, const std::string& s, int a) {
                type = rt;
                offset = off;
                symbol = s;
                addend = a;
            }

        };

        struct Section {

            unsigned int number;
            unsigned int size;
            std::unique_ptr<int[]> data;
            std::list<std::unique_ptr<LiteralPool>> literal_pools;
            std::list<std::unique_ptr<RelocationEntry>> relocation_table;

            Section(unsigned int num, unsigned int sz) {
                number = num;
                size = sz;
                data = std::make_unique<int[]>(sz);

                /*for (int i = 0; i < sz; i++) {
                    data[i] = 0;
                }*/
            }

        };
	
	    // Polja
        std::string input_file, output_file;
        unsigned int location_counter, line_num;
        std::string current_section;
        SymTab* symtab;

        std::unordered_map<std::string, Section*> section_table;
        std::list<std::string> section_order;
        std::list<std::string> symbol_order;

        std::vector<std::pair<bool, std::vector<int>>> instructions;
        std::list<std::pair<std::string, std::vector<unsigned int>>> literal_table;
        std::list<std::unique_ptr<LiteralPool>> literal_pools;
        //std::list<std::pair<unsigned int, std::string>> literal_bpe_entries;
        std::list<std::unique_ptr<RelocationEntry>> relocation_entries;
        std::list<std::string> bp_symbols;

        // Pomocni metodi
        void processLabel(std::string);
        void createData(bool&, unsigned int&, std::unique_ptr<InstructionParameters>&);
        void createSection(bool);
        void addRelocationEntry(std::list<std::unique_ptr<RelocationEntry>>&, std::string&, std::string&, unsigned int);
};

#endif //SINGLE_PASS_ASSEMBLER_H
