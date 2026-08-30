import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import java.util.Map;

import aether.ghidra.bridge.Json;
import aether.ghidra.program.AetherRttiInheritanceAnalyzer;
import aether.ghidra.program.ProgramRegistry;

/** Runs the AETHER analyzer after an external class-recovery script for integration testing. */
public class AetherRttiReprocessSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        if (currentProgram == null) {
            throw new IllegalStateException("AETHER RTTI smoke test requires an imported Program");
        }
        AetherRttiInheritanceAnalyzer analyzer = new AetherRttiInheritanceAnalyzer();
        analyzer.added(currentProgram, currentProgram.getMemory().getAllInitializedAddressSet(), monitor,
            new MessageLog());
        Options options = currentProgram.getOptions("AETHER");
        String analysis = options.getString("rtti_analysis", null);
        if (analysis == null) {
            throw new IllegalStateException("AETHER RTTI analyzer did not persist its analysis output");
        }
        require(analysis.contains("\"name\":\"Child\""), "Recovered Child class is missing");
        require(analysis.contains("\"name\":\"Mid\""), "Recovered Mid class is missing");
        require(analysis.contains("\"name\":\"Other\""), "Recovered Other class is missing");
        require(analysis.contains("\"parent_class\":\"Mid\""), "Child/Mid vtable link is missing");
        require(analysis.contains("\"parent_class\":\"Other\""), "Child/Other vtable link is missing");
        require(analysis.contains("\"relation\":\"override\""), "Virtual override relation is missing");
        ProgramRegistry registry = new ProgramRegistry(currentProgram);
        String programId = registry.idFor(currentProgram);
        Map<String, Object> child = registry.invoke(programId, "get_struct",
            Map.of("path", "/ClassDataTypes/Child/Child"));
        String childJson = Json.stringify(child);
        require(childJson.contains("\"inheritance_chain\":[\"Mid\",\"Base\",\"Other\"]"),
            "get_struct did not expose the transitive inheritance chain");
        require(childJson.contains("\"derived_classes\""),
            "get_struct did not expose derived class metadata");
        require(childJson.contains("\"group_structures\""),
            "get_struct did not expose grouped class and vtable structures");
        require(childJson.contains("\"role\":\"data class\""),
            "Grouped structures did not include the class data structure");
        require(childJson.contains("\"role\":\"vftable\""),
            "Grouped structures did not include a vftable");
        Map<String, Object> classes = registry.invoke(programId, "list_struct",
            Map.of("kind", "class", "grouped", true, "limit", 1000));
        String classJson = Json.stringify(classes);
        require(classJson.contains("\"total\":4"), "Class structures were not grouped by logical class");
        require(classJson.contains("\"name\":\"Base_data\""), "Grouped Base data structure is missing");
        require(classJson.contains("\"name\":\"Base_vftable\""), "Grouped Base vftable structure is missing");
        require(classJson.contains("\"name\":\"Base_vftable\",\"path\":\"/ClassDataTypes/Base/Base_vftable\""),
            "Grouped Base vftable path is missing");
        require(classJson.contains("\"address\":{\"space\":\"ram\",\"offset\":\"103d48\"}"),
            "Grouped Base vftable address is missing");
        require(!classJson.contains("\"class_name\":\"Base_data\""), "Base_data leaked as a separate class");
        require(!classJson.contains("\"role\":\"vtable\",\"name\":\"Base::vtable\""),
            "Metadata-only Base vtable leaked into grouped structures");
        println("AETHER_RTTI_REPROCESS_SMOKE_OK");
        println(analysis);
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
