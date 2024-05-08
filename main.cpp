#include <LIEF/ELF.hpp>
#include <capstone/capstone.h>
#include <cctype>
#include <iostream>
#include <map>

int main(int argc, char **argv) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <ELF file>" << std::endl;
        return 1;
    }

    const std::string elf_file_path = argv[1];

    auto binary = LIEF::ELF::Parser::parse(elf_file_path);

    // This `binary` should contain a reference to the ELF file
    // but I don't know how to get it, so I'll use the following stupid method to read it again
    FILE *fp = fopen(elf_file_path.c_str(), "rb");
    if (!fp) {
        std::cerr << "Failed to open file" << std::endl;
        return 1;
    }
    const char *elf_mem = nullptr;
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    elf_mem = reinterpret_cast<const char *>(malloc(size));
    if (!elf_mem) {
        std::cerr << "Failed to allocate memory" << std::endl;
        return 1;
    }
    fread(const_cast<char *>(elf_mem), 1, size, fp);
    const auto base = reinterpret_cast<uintptr_t>(elf_mem);
    fclose(fp);

    std::map<uint64_t, std::string> string_map;

    try {
        const auto &segments = binary->segments();

        auto rodata_section = binary->get_section(".rodata");
        if (!rodata_section) {
            std::cerr << "No .rodata section found in the ELF file" << std::endl;
            return 1;
        }

        const uint64_t rodata_start = rodata_section->virtual_address();
        const uint64_t rodata_size = rodata_section->size();
        auto rodata_data = rodata_section->content();

        for (uint64_t offset = 0; offset < rodata_size; ++offset) {
            const uint8_t *current_ptr = rodata_data.begin() + offset;

            if (*current_ptr != '\0') {
                const char *string_start = reinterpret_cast<const char *>(current_ptr);
                const char *string_end = string_start;
                while (*string_end != '\0') {
                    ++string_end;
                }

                if (string_end != string_start) {
                    std::string str(string_start, string_end - string_start);
                    string_map.emplace(rodata_start + offset, str);
                }

                offset += string_end - string_start;
            }
        }

        std::map<uint64_t, std::string> string_map_temp;
        for (const auto &entry : string_map) {
            const std::string &str = entry.second;
            bool is_string = true;
            for (char c : str) {
                // If the character is not a printable character and is not a newline character, it is judged as a non-string
                if (!std::isprint(static_cast<unsigned char>(c)) && c != '\n') {
                    is_string = false;
                    break;
                }
            }
            if (is_string) {
                string_map_temp.emplace(entry.first, str);
            }
        }

        string_map = string_map_temp;

        std::cout << "String map contains " << string_map.size() << " strings" << std::endl;

        // for (const auto &entry : string_map) {
        //     if (entry.second.find("il2cpp_init") != std::string::npos) {
        //         std::cout << "String at address 0x" << std::hex << entry.first << ": " << entry.second << std::endl;
        //     }
        // }

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    std::map<uintptr_t, uintptr_t>
        section_map;
    const auto &segments = binary->segments();
    for (const auto &segment : segments) {
        const auto &t = segment.type();
        if (t == LIEF::ELF::SEGMENT_TYPES::PT_LOAD) {
            for (const auto &section : segment.sections()) {
                const auto start = section.file_offset();
                const auto end = start + section.size();
                const auto name = section.name();
                std::cout << "Section " << name << " starts at 0x" << std::hex << start << " and ends at 0x" << end << std::endl;
                section_map.emplace(start, end);
            }
        }
    }

    std::map<uintptr_t, uintptr_t> section_map1;
    for (const auto &entry : section_map) {
        const auto &start = entry.first;
        const auto &end = entry.second;
        const auto start1 = reinterpret_cast<uintptr_t>(elf_mem) + start;
        const auto end1 = reinterpret_cast<uintptr_t>(elf_mem) + end;
        section_map1.emplace(start1, end1);
    }

    // 初始化capstone arm64
    csh handle;
    cs_insn *insn;
    if (cs_open(cs_arch::CS_ARCH_AARCH64, CS_MODE_ARM, &handle) != CS_ERR_OK) {
        std::cerr << "Failed to initialize Capstone" << std::endl;
        return 1;
    }

    // strings ref by asm instructions
    std::map<uintptr_t, std::vector<uintptr_t>> ref_string_map;

    // loop for each section, find adrp and add instructions
    // adrp x0, #0x9e8000
    // add x0, x0, #0x6d5
    for (const auto &entry : section_map) {
        const auto start = base + entry.first;
        const auto end = base + entry.second;

        std::cout << "Disassembling section from 0x" << std::hex << start << " to 0x" << end << std::endl;

        int count = 0;
        try {
            size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(start), end - start, start, 0, &insn);
            if (count > 0) {
                for (size_t i = 0; i < count - 1; ++i) {
                    if (strcmp(insn[i].mnemonic, "adrp") == 0 &&
                        strcmp(insn[i + 1].mnemonic, "add") == 0) {
                        const auto addr_relative = insn[i].address - base;

                        // adrp x8, 0xb40000768e1d5000
                        auto ins_1_str = std::string(insn[i].mnemonic) + " " + std::string(insn[i].op_str);
                        //  add x8, x8, #0x2b0
                        auto ins_2_str = std::string(insn[i + 1].mnemonic) + " " + std::string(insn[i + 1].op_str);

                        // adrp x13, 0xb4000078f7e8f000 add w15, w15, #4, lsl #12
                        if (ins_1_str.find("w") != std::string::npos || ins_2_str.find("w") != std::string::npos) {
                            continue;
                        }

                        // std::cout
                        //     << "[ " << ++count << " ]" << "Found at address 0x" << std::hex << addr_relative << " | "
                        //     << ins_1_str << " "
                        //     << ins_2_str << std::endl;E6DA2D E6E07D

                        auto op_1 = ins_1_str.substr(ins_1_str.find_last_of(",") + 2);
                        auto op_2 = ins_2_str.substr(ins_2_str.find_last_of(",") + 3);
                        // op_1: 0xb4000074f867c000 op_2: 0xea
                        // std::cout << "op_1: " << std::hex << op_1 << " op_2: " << op_2 << std::endl;

                        try {
                            uintptr_t op_1_value = std::stoull(op_1, nullptr, 16);
                            uintptr_t op_2_value = std::stoull(op_2, nullptr, 16);

                            const auto addr_absolute = op_1_value + op_2_value - base;

                            auto it = string_map.find(addr_absolute);

                            // std::cout << "op_1_value: " << std::hex << op_1_value << " op_2_value: " << op_2_value << " addr_absolute: " << addr_absolute << " base: " << base << std::endl;

                            if (it != string_map.end()) {
                                ref_string_map[addr_absolute].push_back(insn[i].address - base);
                            }

                        } catch (const std::exception &e) {
                            // std::cerr << e.what() << '\n';
                        }
                    }
                }
                cs_free(insn, count);
            }
        } catch (const std::exception &e) {
            std::cerr << e.what() << '\n';
        }
    }

    uintptr_t LookupSymbolNearAddress = 0;

    // print ref_string_map
    // format :
    // "string" @ 0x0000000000000000 is referenced by instructions at
    //          0x0000000000000000
    //          0x0000000000000000
    for (const auto &entry : ref_string_map) {
        const auto addr_relative = entry.first;
        const auto &addrs_absolute = entry.second;
        const auto &current_string = string_map[addr_relative];

        std::cout << "String at address 0x" << std::hex << addr_relative << " <- '" << current_string << "'" << std::endl;
        for (const auto &addr_absolute : addrs_absolute) {
            std::cout << "\t0x" << std::hex << addr_absolute << std::endl;
            if (current_string == "il2cpp_init" && !LookupSymbolNearAddress) {
                LookupSymbolNearAddress = addr_absolute;
            }
        }
    }

    // print LookupSymbol
    std::cout << "LookupSymbolNearAddress @ 0x" << std::hex << LookupSymbolNearAddress << std::endl;
    if (!LookupSymbolNearAddress) {
        std::cerr << "LookupSymbolNearAddress not found" << std::endl;
        return 1;
    }

    // + 2 instruction
    auto LookupSymbol = LookupSymbolNearAddress + 4 + 2 * 4 + base;

    // capstone parse
    try {
        size_t count = cs_disasm(handle, reinterpret_cast<const uint8_t *>(LookupSymbol), base, LookupSymbol, 0, &insn);
        count = 1;
        for (size_t i = 0; i < count; ++i) {
            // bl	0x74e78e39f8
            const std::string ins_str = insn[i].op_str;
            // get op value
            auto op = ins_str.substr(ins_str.find_last_of(" ") + 1);
            // to uintptr_t
            uintptr_t op_value = std::stoull(op, nullptr, 16) - base;
            std::cout << "0x" << std::hex << insn[i].address << ":\t" << insn[i].mnemonic << "\t" << insn[i].op_str << std::endl;
            std::cout << "Find LookupSymbol @ 0x" << std::hex << op_value << std::endl;
        }
        cs_free(insn, count);
    } catch (const std::exception &e) {
        // std::cerr << e.what() << '\n';
    }

    cs_close(&handle);
    return 0;
}
