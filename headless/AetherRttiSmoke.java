import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;

/** Verifies that the AETHER RTTI analyzer ran during headless Auto Analyze. */
public class AetherRttiSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AETHER RTTI smoke test requires an imported Program");
        }
        Options options = currentProgram.getOptions("AETHER");
        String analysis = options.getString("rtti_analysis", null);
        if (analysis == null) {
            throw new IllegalStateException("AETHER RTTI analyzer did not persist its analysis output");
        }
        println("AETHER_RTTI_ANALYZER_SMOKE_OK");
        println(analysis);
    }
}
