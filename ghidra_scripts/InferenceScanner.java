import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

/**
 * InferenceScanner.java — Ghidra headless script for single-file feature extraction.
 *
 * Extracts all function mnemonics from a binary and writes them to a text file.
 * Format matches the DiverseScanner.java output used during model training:
 *
 *   FUNCTION: funcName
 *   PUSH
 *   MOV
 *   SUB
 *   ---
 *
 * Usage (via analyzeHeadless):
 *   analyzeHeadless <projDir> TempProject -import <binary>
 *       -scriptPath <thisDir> -postScript InferenceScanner.java <outputDir>
 *       -deleteProject
 *
 * The script argument <outputDir> controls where the _features.txt file is saved.
 * If no argument is given, it defaults to the current working directory.
 */
public class InferenceScanner extends GhidraScript {

    @Override
    public void run() throws Exception {
        Program program = currentProgram;
        if (program == null) {
            println("ERROR: No program loaded.");
            return;
        }

        String programName = program.getName();
        println("[InferenceScanner] Extracting features for: " + programName);

        // Determine output directory from script arguments
        String[] args = getScriptArgs();
        File outDir;
        if (args.length > 0 && args[0] != null && !args[0].isEmpty()) {
            outDir = new File(args[0]);
        } else {
            outDir = new File(".");
        }

        if (!outDir.exists()) {
            outDir.mkdirs();
        }

        // Create output file: <programName>_features.txt
        File outputFile = new File(outDir, programName + "_features.txt");
        PrintWriter writer = new PrintWriter(new FileWriter(outputFile));

        // Iterate through all functions and extract mnemonics
        FunctionManager functionManager = program.getFunctionManager();
        FunctionIterator functions = functionManager.getFunctions(true);

        int funcCount = 0;
        int instrCount = 0;

        while (functions.hasNext()) {
            Function function = functions.next();
            writer.println("FUNCTION: " + function.getName());

            InstructionIterator instructions =
                program.getListing().getInstructions(function.getBody(), true);

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                writer.println(instr.getMnemonicString());
                instrCount++;
            }

            writer.println("---");
            funcCount++;
        }

        writer.close();
        println("[InferenceScanner] Done. Functions: " + funcCount
                + ", Instructions: " + instrCount
                + ", Output: " + outputFile.getAbsolutePath());
    }
}
