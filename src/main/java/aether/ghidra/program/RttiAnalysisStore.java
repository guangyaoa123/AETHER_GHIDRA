package aether.ghidra.program;

import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.framework.options.Options;
import ghidra.program.model.listing.Program;

import aether.ghidra.bridge.Json;

/** Persists the read-only class graph produced by the AETHER RTTI analyzer. */
final class RttiAnalysisStore {
	static final String OPTION_NAME = "rtti_analysis";
	private static final String OPTIONS_NAME = "AETHER";
	private static final int VERSION = 2;

	private RttiAnalysisStore() {
	}

	static Map<String, Map<String, Object>> load(Program program) {
		Options options = program.getOptions(OPTIONS_NAME);
		String encoded = options.getString(OPTION_NAME, "{}");
		try {
			Map<String, Object> document = Json.object(Json.parse(encoded));
			Object rawClasses = document.get("classes");
			if (!(rawClasses instanceof Map<?, ?> classes)) {
				return new LinkedHashMap<>();
			}
			Map<String, Map<String, Object>> result = new LinkedHashMap<>();
			for (Map.Entry<?, ?> entry : classes.entrySet()) {
				if (entry.getKey() instanceof String key && entry.getValue() instanceof Map<?, ?> value) {
					result.put(key, new LinkedHashMap<>(Json.object(value)));
				}
			}
			return result;
		}
		catch (RuntimeException ignored) {
			return new LinkedHashMap<>();
		}
	}

	static void save(Program program, Map<String, Map<String, Object>> classes,
		Map<String, Object> diagnostics) {
		Map<String, Object> document = new LinkedHashMap<>();
		document.put("version", VERSION);
		document.put("classes", new LinkedHashMap<>(classes));
		document.put("diagnostics", diagnostics == null ? Map.of() : diagnostics);
		program.getOptions(OPTIONS_NAME).setString(OPTION_NAME, Json.stringify(document));
	}
}
