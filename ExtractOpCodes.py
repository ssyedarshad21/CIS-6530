# ExtractOpCodes.py for Ghidra

# Import necessary Ghidra modules
from ghidra.program.model.listing import Listing
from ghidra.program.model.mem import MemoryAccessException

# Ensure a program is loaded before running the script
if currentProgram is None:
    print("Error: No program loaded. Please open a binary in GHIDRA and run the script again.")
    exit(1)

# Create the output file
program_name = currentProgram.getExecutablePath()
base_name = program_name[program_name.rfind("/") + 1:]
opcode_filename = base_name + ".opcode"  # Output file name

listing = currentProgram.getListing()
last_section_name = ""

# Open the output file for writing
with open(opcode_filename, 'w') as writer:
    count = 0
    max_instructions = 10000  # Optional limit to prevent long execution times

    # Iterate through each instruction in the program
    instructions = listing.getInstructions(True)
    for instruction in instructions:
        if count >= max_instructions:
            print("Reached max instruction limit, stopping early...")
            break

        # Extract the mnemonic (OpCode)
        mnemonic = instruction.getMnemonicString()
        instruction_address = instruction.getAddress()

        # Find the section name
        block = currentProgram.getMemory().getBlock(instruction_address)
        section_name = block.getName() if block else "Unknown"

        # Write section header if it's different from the last
        if section_name != last_section_name:
            if last_section_name:
                writer.write("\n---\n\n")  # Add a delimiter and newline between different sections
            writer.write(section_name + ":\n")
            last_section_name = section_name

        # Write the mnemonic to the file
        writer.write(mnemonic + "\n")
        count += 1

        # Print progress every 5000 instructions
        if count % 5000 == 0:
            print("Processed {} instructions...".format(count))

print("OpCodes successfully extracted to {}".format(opcode_filename))

