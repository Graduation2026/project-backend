import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.block.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.FlowType;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import com.google.gson.*;

/**
 * ExtractAllCFGs.java — Ghidra headless script for extracting all function CFGs.
 * Saves the extracted CFGs as a single JSON file.
 *
 * Usage (via analyzeHeadless):
 *   analyzeHeadless <projDir> TempProject -import <binary>
 *       -scriptPath <thisDir> -postScript ExtractAllCFGs.java <outputJsonPath>
 *       -deleteProject
 */
public class ExtractAllCFGs extends GhidraScript {
    @Override
    protected void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("ERROR: Missing output file path argument.");
            return;
        }
        String outputPath = args[0];

        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();
        FunctionManager funcManager = currentProgram.getFunctionManager();
        Listing listing = currentProgram.getListing();
        Gson gson = new Gson();

        println("[ExtractAllCFGs] Total functions in manager: " + funcManager.getFunctionCount());

        JsonArray functionsArray = new JsonArray();
        FunctionIterator funcIter = funcManager.getFunctions(true);

        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            String fname = func.getName();

            // Skip thunks and compiler-internal symbols (double-underscore),
            // but allow single-underscore names — object files (.o) use them
            // for ALL user functions (e.g. _main, _vulnerable_function).
            if (func.isThunk() || fname.startsWith("__") || fname.startsWith("sys_")) {
                continue;
            }

            // Trace function body using branch targets
            Address entry = func.getEntryPoint();
            Set<Address> seen = new HashSet<>();
            Deque<Address> worklist = new ArrayDeque<>();
            worklist.add(entry);

            while (!worklist.isEmpty()) {
                Address addr = worklist.poll();
                if (!seen.add(addr)) continue;

                // Disassemble just this address
                ghidra.app.cmd.disassemble.DisassembleCommand dcmd =
                    new ghidra.app.cmd.disassemble.DisassembleCommand(new AddressSet(addr), null, false);
                dcmd.applyTo(currentProgram, monitor);

                Instruction instr = listing.getInstructionAt(addr);
                if (instr == null) continue;

                Address ft = instr.getFallThrough();
                if (ft != null && !seen.contains(ft)) worklist.add(ft);

                FlowType flowType = instr.getFlowType();
                if (!flowType.isCall()) {
                    Address[] flows = instr.getFlows();
                    if (flows != null) {
                        for (Address flowAddr : flows) {
                            if (!seen.contains(flowAddr)) worklist.add(flowAddr);
                        }
                    }
                }
            }

            // Build body address set
            AddressSet bodySet = new AddressSet();
            for (Address a : seen) {
                Instruction instr = listing.getInstructionAt(a);
                if (instr != null) {
                    bodySet.add(instr.getMinAddress(), instr.getMaxAddress());
                }
            }

            // Extract blocks and CFG edges
            BasicBlockModel blockModel = new BasicBlockModel(currentProgram);
            JsonArray nodes = new JsonArray();
            JsonArray edges = new JsonArray();
            Map<String, Integer> blocks = new HashMap<>();

            CodeBlockIterator blockIter = blockModel.getCodeBlocksContaining(bodySet, monitor);
            int blockIndex = 0;
            List<CodeBlock> blockList = new ArrayList<>();
            while (blockIter.hasNext()) {
                CodeBlock block = blockIter.next();
                blockList.add(block);
                blocks.put(block.getMinAddress().toString(), blockIndex);

                JsonArray instructions = new JsonArray();
                InstructionIterator instrIter = listing.getInstructions(block, true);
                while (instrIter.hasNext()) {
                    Instruction instr = instrIter.next();
                    String instrStr = instr.toString();
                    
                    Address[] flowAddrs = instr.getFlows();
                    if (flowAddrs != null && flowAddrs.length > 0) {
                        Address target = flowAddrs[0];
                        Function targetFunc = currentProgram.getFunctionManager().getFunctionAt(target);
                        if (targetFunc != null) {
                            instrStr += " // " + targetFunc.getName();
                        } else {
                            ghidra.program.model.symbol.Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(target);
                            if (sym != null) {
                                instrStr += " // " + sym.getName();
                            }
                        }
                    } else {
                        ghidra.program.model.symbol.Reference[] refs = instr.getReferencesFrom();
                        if (refs != null && refs.length > 0) {
                            Address target = refs[0].getToAddress();
                            ghidra.program.model.symbol.Symbol sym = currentProgram.getSymbolTable().getPrimarySymbol(target);
                            if (sym != null) {
                                instrStr += " // " + sym.getName();
                            }
                        }
                    }
                    
                    instructions.add(instrStr);
                }

                JsonObject node = new JsonObject();
                node.addProperty("id", blockIndex);
                node.add("instructions", instructions);
                nodes.add(node);

                blockIndex++;
            }

            // Skip empty functions (0 blocks = extraction failed) or very large functions (200+ blocks = likely data)
            // Single-block functions ARE included — they can contain dangerous calls like gets()
            if (blockIndex < 1 || blockIndex > 200) {
                continue;
            }

            for (int i = 0; i < blockList.size(); i++) {
                CodeBlock block = blockList.get(i);
                CodeBlockReferenceIterator dests = block.getDestinations(monitor);
                while (dests.hasNext()) {
                    CodeBlockReference ref = dests.next();
                    String destAddr = ref.getDestinationAddress().toString();
                    if (blocks.containsKey(destAddr)) {
                        JsonArray edge = new JsonArray();
                        edge.add(i);
                        edge.add(blocks.get(destAddr));
                        edges.add(edge);
                    }
                }
            }

            JsonObject functionObj = new JsonObject();
            functionObj.addProperty("function_name", fname);
            functionObj.add("nodes", nodes);
            functionObj.add("edges", edges);
            functionsArray.add(functionObj);
        }

        // Write to output file
        File outFile = new File(outputPath);
        File parentDir = outFile.getParentFile();
        if (parentDir != null && !parentDir.exists()) {
            parentDir.mkdirs();
        }

        try (FileWriter writer = new FileWriter(outFile)) {
            gson.toJson(functionsArray, writer);
        }

        println("[ExtractAllCFGs] Done. Saved " + functionsArray.size() + " function CFGs to: " + outputPath);
    }
}
