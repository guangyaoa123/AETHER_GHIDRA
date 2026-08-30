import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;

import aether.ghidra.program.AetherRttiInheritanceAnalyzer;

/** Runs Ghidra class recovery followed by the AETHER RTTI inheritance analyzer. */
public class AetherRecoverClassesAndAnalyze extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AETHER RTTI recovery requires an imported Program");
        }
        println("Running Ghidra RecoverClassesFromRTTIScript.java...");
        runScript("RecoverClassesFromRTTIScript.java");
        println("Running AETHER RTTI Inheritance analyzer...");
        new AetherRttiInheritanceAnalyzer().added(currentProgram,
            currentProgram.getMemory().getAllInitializedAddressSet(), monitor, new MessageLog());
        println("AETHER RTTI recovery and inheritance analysis complete.");
    }
}
