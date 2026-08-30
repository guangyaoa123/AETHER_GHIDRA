import java.util.List;
import java.util.Map;

import aether.ghidra.bridge.Json;
import aether.ghidra.program.ProgramRegistry;
import ghidra.app.script.GhidraScript;

/** Verifies that class details expose identified non-virtual functions. */
public class AetherClassFunctionsSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        String path = getScriptArgs().length == 0 ? "/ClassDataTypes/Child/Child" : getScriptArgs()[0];
        ProgramRegistry registry = new ProgramRegistry(currentProgram);
        Map<String, Object> result = registry.invoke(registry.idFor(currentProgram), "get_struct",
            Map.of("path", path));
        Map<String, Object> classInfo = Json.object(result.get("class"));
        Object rawFunctions = classInfo.get("non_virtual_functions");
        if (!(rawFunctions instanceof List<?> functions)) {
            throw new IllegalStateException("Class details did not include non_virtual_functions");
        }
        println("AETHER_CLASS_FUNCTIONS_SMOKE_OK count=" + functions.size());
        for (Object raw : functions) {
            Map<String, Object> function = Json.object(raw);
            println(function.get("name") + " " + function.get("address"));
        }
    }
}
