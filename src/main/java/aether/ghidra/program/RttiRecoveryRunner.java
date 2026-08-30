package aether.ghidra.program;

import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.task.TaskMonitor;

/** Runs Ghidra's RTTI recovery and then persists AETHER's class graph. */
public final class RttiRecoveryRunner {
    private RttiRecoveryRunner() {
    }

    public static void run(PluginTool tool, Program program, TaskMonitor monitor) throws Exception {
        int transaction = program.startTransaction("AETHER: recover C++ RTTI classes");
        boolean commit = false;
        try {
            Options options = program.getOptions("AETHER");
            options.setString("rtti_import_recovery_state", "running");
            runRecovery(tool, program, monitor);
            options.setString("rtti_import_recovery_state", "completed");
            commit = true;
        }
        catch (Exception error) {
            program.getOptions("AETHER").setString("rtti_import_recovery_state", "failed");
            throw error;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
    }

    private static void runRecovery(PluginTool tool, Program program, TaskMonitor monitor) throws Exception {
        ResourceFile source = GhidraScriptUtil.findScriptByName("RecoverClassesFromRTTIScript.java");
        if (source == null) {
            throw new IllegalStateException("Ghidra RecoverClassesFromRTTIScript.java was not found");
        }
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
        if (provider == null) {
            throw new IllegalStateException("No Ghidra script provider for " + source.getName());
        }
        PrintWriter output = new PrintWriter(System.out, true);
        GhidraScript script = provider.getScriptInstance(source, output);
        GhidraState state = new GhidraState(tool, tool.getProject(), program, null, null, null);
        script.execute(state, monitor, output);
        new AetherRttiInheritanceAnalyzer().added(program,
            program.getMemory().getAllInitializedAddressSet(), monitor, new MessageLog());
    }
}
