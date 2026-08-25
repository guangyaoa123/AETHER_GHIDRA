package aether.ghidra.program;

import java.util.LinkedHashMap;
import java.util.Map;

import ghidra.program.model.listing.Program;

/** A session-scoped identity and lock for one live Ghidra Program. */
final class ProgramContext {
	private final String id;
	private final Program program;
	private boolean active;

	ProgramContext(String id, Program program) {
		this.id = id;
		this.program = program;
	}

	String id() {
		return id;
	}

	Program program() {
		return program;
	}

	void setActive(boolean active) {
		this.active = active;
	}

	Map<String, Object> metadata() {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("program_id", id);
		result.put("name", safe(program.getName()));
		result.put("executable_path", safe(program.getExecutablePath()));
		result.put("executable_format", safe(program.getExecutableFormat()));
		result.put("md5", safe(program.getExecutableMD5()));
		result.put("sha256", safe(program.getExecutableSHA256()));
		result.put("language", safe(program.getLanguageID().getIdAsString()));
		result.put("compiler", safe(program.getCompiler()));
		result.put("compiler_spec", safe(program.getCompilerSpec().getCompilerSpecID().getIdAsString()));
		result.put("function_count", program.getFunctionManager().getFunctionCount());
		result.put("active", active);
		return result;
	}

	private static String safe(String value) {
		return value == null ? "" : value;
	}
}
