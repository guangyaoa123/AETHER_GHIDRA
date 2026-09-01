package aether.ghidra.program;

import java.io.PrintWriter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.options.Options;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.app.util.importer.MessageLog;
import ghidra.util.task.TaskMonitor;

/** Runs Ghidra's RTTI recovery and then persists AETHER's class graph. */
public final class RttiRecoveryRunner {
    private RttiRecoveryRunner() {
    }

    public static void run(PluginTool tool, Program program, TaskMonitor monitor) throws Exception {
		run(tool, tool.getProject(), program, monitor);
	}

	public static void run(Project project, Program program, TaskMonitor monitor) throws Exception {
		run(null, project, program, monitor);
	}

    private static void run(PluginTool tool, Project project, Program program, TaskMonitor monitor) throws Exception {
		if (!GhidraProgramUtilities.isAnalyzed(program)) {
			setRecoveryState(program, "failed");
			throw new IllegalStateException(
				"Ghidra auto-analysis has not completed; RTTI recovery cannot run yet");
		}
        int transaction = program.startTransaction("AETHER: recover C++ RTTI classes");
        boolean commit = false;
		Exception failure = null;
        try {
            Options options = program.getOptions("AETHER");
            options.setString("rtti_import_recovery_state", "running");
            runRecovery(tool, project, program, monitor);
            options.setString("rtti_import_recovery_state", "completed");
            commit = true;
        }
        catch (Exception error) {
			failure = error;
        }
        finally {
            program.endTransaction(transaction, commit);
        }
		if (failure != null) {
			setRecoveryState(program, "failed");
			throw failure;
		}
    }

	/**
	 * Re-derives only the AETHER class graph from existing RTTI evidence and
	 * ClassDataTypes structures. Skips Ghidra class recovery entirely so callers
	 * can refresh cheaply after metadata changes; the store ignores identical
	 * writes, so an unchanged graph produces no Program change events.
	 */
	public static void refreshClassGraph(Program program, TaskMonitor monitor) throws Exception {
		int transaction = program.startTransaction("AETHER: refresh class graph");
		boolean commit = false;
		Exception failure = null;
		try {
			new AetherRttiInheritanceAnalyzer().added(program,
				program.getMemory().getAllInitializedAddressSet(), monitor, new MessageLog());
			commit = true;
		}
		catch (Exception error) {
			failure = error;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		if (failure != null) {
			throw failure;
		}
	}

	private static void setRecoveryState(Program program, String state) {
		int transaction = program.startTransaction("AETHER: update RTTI recovery state");
		try {
			program.getOptions("AETHER").setString("rtti_import_recovery_state", state);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

    private static void runRecovery(PluginTool tool, Project project, Program program, TaskMonitor monitor) throws Exception {
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
        GhidraState state = new GhidraState(tool, project, program, null, null, null);
        script.execute(state, monitor, output);
        new AetherRttiInheritanceAnalyzer().added(program,
            program.getMemory().getAllInitializedAddressSet(), monitor, new MessageLog());
    }
}
