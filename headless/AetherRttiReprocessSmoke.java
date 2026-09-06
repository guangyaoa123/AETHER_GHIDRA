import ghidra.app.script.GhidraScript;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.util.Map;
import java.util.List;

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
        require(verifyVirtualRename(registry, programId, child),
            "A recovered virtual function did not update its applied vtable slot field");
        println("AETHER_RTTI_REPROCESS_SMOKE_OK");
        println(analysis);
    }

    private boolean verifyVirtualRename(ProgramRegistry registry, String programId,
        Map<String, Object> child) throws Exception {
        Map<String, Object> classModel = objectMap(child.get("class"));
        if (classModel == null) {
            return false;
        }
        for (Map<String, Object> vtable : mapList(classModel.get("vtables"))) {
            for (Map<String, Object> slot : mapList(vtable.get("slots"))) {
                Map<String, Object> functionInfo = objectMap(slot.get("function"));
                Map<String, Object> addressMap = objectMap(functionInfo == null ? null : functionInfo.get("address"));
                if (addressMap == null) {
                    continue;
                }
                Address address = currentAddress(addressMap);
                Function function = currentProgram.getFunctionManager().getFunctionAt(address);
                if (function == null) {
                    continue;
                }
                String original = function.getName();
                try {
                    Map<String, Object> renamed = registry.invoke(programId, "rename_function", Map.of(
                        "address", addressMap, "name", "aether_virtual_rename_smoke",
                        "propagate_virtual", false));
                    List<Map<String, Object>> fields = mapList(renamed.get("vtable_fields"));
                    if (fields.isEmpty()) {
                        continue;
                    }
                    for (Map<String, Object> field : fields) {
                        Map<String, Object> structure = registry.invoke(programId, "get_struct",
                            Map.of("path", field.get("structure")));
                        for (Map<String, Object> current : mapList(structure.get("fields"))) {
                            if (field.get("ordinal").equals(current.get("ordinal"))) {
                                require("aether_virtual_rename_smoke".equals(current.get("name")),
                                    "Updated vtable field was not readable after rename");
                                return true;
                            }
                        }
                    }
                }
                finally {
                    registry.invoke(programId, "rename_function", Map.of(
                        "address", addressMap, "name", original, "propagate_virtual", false));
                }
            }
        }
        return false;
    }

    private Address currentAddress(Map<String, Object> address) {
        return currentProgram.getAddressFactory().getAddress(
            address.get("space") + ":" + address.get("offset"));
    }

    private static Map<String, Object> objectMap(Object value) {
        return value instanceof Map<?, ?> map ? Json.object(map) : null;
    }

    private static List<Map<String, Object>> mapList(Object value) {
        if (!(value instanceof Iterable<?> values)) {
            return List.of();
        }
        java.util.ArrayList<Map<String, Object>> result = new java.util.ArrayList<>();
        for (Object item : values) {
            if (item instanceof Map<?, ?> map) {
                result.add(Json.object(map));
            }
        }
        return result;
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
