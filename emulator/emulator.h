#ifndef EMULATOR_H_
#define EMULATOR_H_

#include <map>
#include <memory>

class Emulator {

    public:
        explicit Emulator(std::string);

        void loadMemory();
        void emulate();
        void displayState() const;

        static void trim(std::string&, const std::string&);
        static int twosComplement(unsigned int, int);

    private:
        // strukture
        struct CPU {
            std::unique_ptr<unsigned int[]> reg;
            std::unique_ptr<unsigned int[]> csr;

            CPU() {
                reg = std::make_unique<unsigned int[]>(16);
                csr = std::make_unique<unsigned int[]>(3);
            }

        };

        std::string input_file;

        std::unique_ptr<CPU> cpu_context;
        // pair<int, bool> je par "vrednost na zadatoj adresi" -- "da li ta adresa pripada steku?"
        std::map<unsigned int, std::pair<int, bool>> source_memory;


        // pomocne funkcije
        unsigned int readFromMemory(unsigned int);
        void writeToMemory(unsigned int, unsigned int);
        void pushToStack(unsigned int);


};

#endif //EMULATOR_H_