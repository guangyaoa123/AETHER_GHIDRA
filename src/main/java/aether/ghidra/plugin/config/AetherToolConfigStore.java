package aether.ghidra.plugin.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import aether.ghidra.bridge.Json;
import aether.ghidra.observability.DebugLog;

/** Reads and writes the grouped chatbot tool policy shared with Python. */
public final class AetherToolConfigStore {
	private static final int VERSION = 2;
	private static final Path DEFAULT_PATH = Path.of(
		System.getProperty("user.home"), ".config", "aether-ghidra", "chatbot-tool-config.json");
	private static final Map<String, Boolean> DEFAULT_GROUPS = Map.ofEntries(
		Map.entry("program_read", true),
		Map.entry("analysis_context", true),
		Map.entry("program_write", false),
		Map.entry("planning", true),
		Map.entry("memory", true),
		Map.entry("conversation", true));
	private static final Map<String, Boolean> ANNOTATION_GROUP_DEFAULTS = Map.ofEntries(
		Map.entry("annotation_read", true), Map.entry("annotation_write", false));
	private static final Map<String, List<String>> LEGACY_TO_GROUP = Map.ofEntries(
		Map.entry("program_read", List.of("list_functions", "get_function_pseudocode",
			"get_data_at_address", "get_xrefs_to")),
		Map.entry("analysis_context", List.of("add_to_function_list", "remove_from_function_list")),
		Map.entry("program_write", List.of("rename_function", "rename_variable", "set_function_comment",
			"set_code_unit_comment", "retype_variable", "update_function_definition")),
		Map.entry("planning", List.of("add_action_plan", "add_task_to_plan", "update_task",
			"remove_task_from_plan", "remove_action_plan")),
		Map.entry("memory", List.of("add_memory", "remove_memory", "search_memory")),
		Map.entry("conversation", List.of("save_summary")),
		Map.entry("annotation_read", List.of("get_function_call_tree", "get_annotation_context")),
		Map.entry("annotation_write", List.of("apply_annotation_batch")));

	private AetherToolConfigStore() {
	}

	public static Map<String, Boolean> loadGroups() {
		Map<String, Boolean> result = new LinkedHashMap<>(DEFAULT_GROUPS);
		result.putAll(ANNOTATION_GROUP_DEFAULTS);
		try {
			if (!Files.exists(DEFAULT_PATH)) {
				return result;
			}
			Map<String, Object> loaded = Json.object(
				Json.parse(Files.readString(DEFAULT_PATH, StandardCharsets.UTF_8)));
			Map<String, Object> groups = Json.optionalObject(loaded, "groups");
			if (loaded.get("version") instanceof Number) {
				for (String group : result.keySet()) {
					if (groups.get(group) instanceof Boolean enabled) {
						result.put(group, enabled);
					}
				}
			}
			else {
				for (Map.Entry<String, List<String>> entry : LEGACY_TO_GROUP.entrySet()) {
					boolean found = false;
					boolean enabled = true;
					for (String tool : entry.getValue()) {
						if (loaded.get(tool) instanceof Boolean value) {
							found = true;
							enabled &= value;
						}
					}
					if (found) {
						result.put(entry.getKey(), enabled);
					}
				}
			}
		}
		catch (IOException | RuntimeException e) {
			DebugLog.debug(AetherToolConfigStore.class,
				"could not read tool configuration: " + e.getClass().getSimpleName());
		}
		return result;
	}

	public static void saveGroups(Map<String, Boolean> groups) {
		Map<String, Object> document = new LinkedHashMap<>();
		document.put("version", VERSION);
		document.put("groups", new LinkedHashMap<>(groups));
		document.put("tools", new LinkedHashMap<>());
		try {
			Files.createDirectories(DEFAULT_PATH.getParent());
			Files.writeString(DEFAULT_PATH, Json.stringify(document) + System.lineSeparator(),
				StandardCharsets.UTF_8);
		}
		catch (IOException e) {
			throw new IllegalStateException("Could not save AETHER tool configuration", e);
		}
	}
}
