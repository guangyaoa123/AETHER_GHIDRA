import aether.ghidra.headless.HeadlessAetherRuntime;

import ghidra.app.script.GhidraScript;

/**
 * Starts the same AETHER bridge and Python agent used by the GUI plugin for the
 * current headless Program. Use AETHER_HEADLESS_DURATION_SEC to control how
 * long the service remains available for external annotation requests.
 */
public class AetherHeadlessScript extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AETHER headless mode requires an imported current Program");
        }
        int bridgePort = integerEnvironment("AETHER_GHIDRA_PORT", 8765);
        int duration = integerEnvironment("AETHER_HEADLESS_DURATION_SEC", 300);
        HeadlessAetherRuntime runtime = new HeadlessAetherRuntime(currentProgram, bridgePort);
        runtime.start();
        try {
            println("AETHER headless bridge listening on http://127.0.0.1:" + runtime.bridgePort());
            println("AETHER headless programs: " + runtime.registry().listPrograms());
            println("AETHER headless runtime active for " + duration + " seconds");
            long deadline = System.currentTimeMillis() + duration * 1000L;
            while (System.currentTimeMillis() < deadline) {
                Thread.sleep(Math.min(1000L, Math.max(1L, deadline - System.currentTimeMillis())));
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
