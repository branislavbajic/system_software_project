This project is supposed to run on Linux OS.

After creating executable files with g++ compiler you can use them like this:

1. Assembler (Translating assembly code to object code)

	- Command format:
		assembler -o output_file_name.o input_file_name.s
		
2. Linker (Linking different object files into one)
	
	- Command format:
		linker -hex -place=section_name@hex_address \
		-o program_name.hex \
		input_file_name1.o input_file_name2.o input_file_name3.o
		
3. Emulator (executing the .hex file)

	- Command format:
		emulator program_name.hex


Additional information about abstract computer architecture and additonal options like specifying start address of individual section will be added later.