package aether.ghidra.observability;

import ghidra.util.Msg;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

/** Small opt-in logger for bridge diagnostics without logging credentials or payloads. */
public final class DebugLog {
	private static final boolean ENABLED = readEnabled();
	private static volatile ConsoleService consoleService;

	private DebugLog() {
	}

	public static boolean enabled() {
		return ENABLED;
	}

	public static void debug(Object source, String message) {
		if (ENABLED) {
			String formatted = "[AETHER DEBUG] " + message;
			Msg.info(source, formatted);
			ConsoleService console = consoleService;
			if (console != null) {
				console.println(formatted);
			}
		}
	}

	public static void configure(PluginTool tool) {
		consoleService = tool == null ? null : tool.getService(ConsoleService.class);
	}

	private static boolean readEnabled() {
		String value = System.getenv("AETHER_GHIDRA_DEBUG");
		return value != null && (value.equalsIgnoreCase("1") || value.equalsIgnoreCase("true") ||
			value.equalsIgnoreCase("yes") || value.equalsIgnoreCase("on"));
	}
}
