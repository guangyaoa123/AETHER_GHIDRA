import aether.ghidra.headless.HeadlessAetherRuntime;

import ghidra.framework.options.Options;
import ghidra.app.script.GhidraScript;
import ghidra.program.util.GhidraProgramUtilities;

/** Starts the AETHER runtime and exposes every Program in the project. */
public class AetherHeadlessScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        int bridgePort = integerEnvironment("AETHER_GHIDRA_PORT", 8765);
        if (currentProgram != null) {
            currentProgram.getOptions("AETHER").setString("rtti_import_recovery_state", "running");
        }
        HeadlessAetherRuntime runtime = new HeadlessAetherRuntime(getState().getProject(), currentProgram, bridgePort);
        runtime.start();
        try {
            println("AETHER headless bridge listening on http://127.0.0.1:" + runtime.bridgePort());
            println("AETHER headless programs: " + runtime.registry().listPrograms());
            if (currentProgram != null) {
                try {
                    Options options = currentProgram.getOptions("AETHER");
                    println("Running Ghidra auto-analysis...");
                    analyzeAll(currentProgram);
                    GhidraProgramUtilities.markProgramAnalyzed(currentProgram);
                    println("Ghidra auto-analysis complete.");
                    println("Running Ghidra RTTI recovery and AETHER inheritance analysis...");
                    runScript("AetherRecoverClassesAndAnalyze.java");
                    options.setString("rtti_import_recovery_state", "completed");
                    println("AETHER import-time RTTI recovery complete.");
                }
                catch (Exception error) {
                    currentProgram.getOptions("AETHER").setString("rtti_import_recovery_state", "failed");
                    println("AETHER import-time RTTI recovery skipped: " + error.getMessage());
                }
            }
            println("AETHER headless runtime active until explicitly closed");
            while (true) {
                Thread.sleep(1000L);
            }
        }
        finally {
            runtime.close();
        }
    }

    private static int integerEnvironment(String name, int fallback) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            int parsed = Integer.parseInt(value);
            if (parsed < 1) {
                throw new NumberFormatException("must be positive");
            }
            return parsed;
        }
        catch (NumberFormatException error) {
            throw new IllegalArgumentException(name + " must be a positive integer", error);
        }
    }
}
