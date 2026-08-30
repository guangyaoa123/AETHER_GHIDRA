import java.util.List;
import java.util.Map;

import aether.ghidra.bridge.Json;
import aether.ghidra.program.ProgramRegistry;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

/** Verifies that displayed decompiler calls round-trip to exact function references. */
public class AetherPseudocodeCallsSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        Function caller = findFunction("rtti_fixture");
        ProgramRegistry registry = new ProgramRegistry(currentProgram);
        String programId = registry.idFor(currentProgram);
        Map<String, Object> result = registry.invoke(programId, "get_function",
            Map.of("address", ProgramRegistry.addressMap(caller.getEntryPoint()), "read_only", true));
        Object rawCalls = result.get("calls");
        if (!(rawCalls instanceof List<?> calls) || calls.isEmpty()) {
            throw new IllegalStateException("Pseudocode did not expose resolved calls");
        }
        for (Object raw : calls) {
            Map<String, Object> call = Json.object(raw);
            Map<String, Object> resolved = registry.invoke(programId, "resolve_pseudocode_call", Map.of(
                "caller_address", ProgramRegistry.addressMap(caller.getEntryPoint()),
                "call_site", call.get("call_site"),
                "display_name", call.get("name")));
            if (!Json.stringify(call.get("target_address")).equals(Json.stringify(resolved.get("target_address"))) ||
                !Json.stringify(call.get("name")).equals(Json.stringify(resolved.get("name")))) {
                throw new IllegalStateException("Pseudocode call resolved to a different function");
            }
        }
        println("AETHER_PSEUDOCODE_CALLS_SMOKE_OK calls=" + calls.size());
    }

    private Function findFunction(String name) {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        while (functions.hasNext()) {
            Function function = functions.next();
            if (name.equals(function.getName())) {
                return function;
            }
        }
        throw new IllegalStateException("Missing fixture function: " + name);
    }
}
