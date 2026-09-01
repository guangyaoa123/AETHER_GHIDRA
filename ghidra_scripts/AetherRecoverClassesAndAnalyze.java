import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.util.GhidraProgramUtilities;

import aether.ghidra.program.AetherRttiInheritanceAnalyzer;

/** Runs Ghidra class recovery followed by the AETHER RTTI analyzer. */
public class AetherRecoverClassesAndAnalyze extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AETHER RTTI recovery requires an imported Program");
        }
        Options aetherOptions = currentProgram.getOptions("AETHER");
        if (!GhidraProgramUtilities.isAnalyzed(currentProgram) &&
            "completed".equals(aetherOptions.getString("rtti_import_recovery_state", ""))) {
            GhidraProgramUtilities.markProgramAnalyzed(currentProgram);
        }
        if (!GhidraProgramUtilities.isAnalyzed(currentProgram)) {
            throw new IllegalStateException(
                "Ghidra auto-analysis has not completed; RTTI recovery cannot run yet");
        }
        println("Running Ghidra RecoverClassesFromRTTIScript.java...");
        runScript("RecoverClassesFromRTTIScript.java");
        println("Running AETHER RTTI Inheritance analyzer...");
        new AetherRttiInheritanceAnalyzer().added(currentProgram,
            currentProgram.getMemory().getAllInitializedAddressSet(), monitor, new MessageLog());
        println("AETHER RTTI recovery and inheritance analysis complete.");
    }
}
