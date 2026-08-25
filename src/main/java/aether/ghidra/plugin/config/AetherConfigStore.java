package aether.ghidra.plugin.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import aether.ghidra.bridge.Json;
import aether.ghidra.observability.DebugLog;

/** Reads and writes the Python agent configuration shared by the GUI and agent. */
public final class AetherConfigStore {
	private static final Path DEFAULT_PATH = Path.of(
		System.getProperty("user.home"), ".config", "aether-ghidra", "config.json");

	private AetherConfigStore() {
	}

	public static Path path() {
		String configured = System.getenv("AETHER_GHIDRA_CONFIG");
		return configured == null || configured.isBlank() ? DEFAULT_PATH : Path.of(configured);
	}

	public static Map<String, Object> load() {
		try {
			if (!Files.exists(path())) {
				return new LinkedHashMap<>();
			}
			return new LinkedHashMap<>(Json.object(
				Json.parse(Files.readString(path(), StandardCharsets.UTF_8))));
		}
		catch (IOException | RuntimeException e) {
			DebugLog.debug(AetherConfigStore.class, "could not read config file: " + e.getClass().getSimpleName());
			return new LinkedHashMap<>();
		}
	}

	public static void save(Map<String, Object> config) {
		try {
			Path configPath = path();
			Files.createDirectories(configPath.toAbsolutePath().getParent());
			Files.writeString(configPath, Json.stringify(config) + System.lineSeparator(),
				StandardCharsets.UTF_8);
			try {
				Files.setPosixFilePermissions(configPath, Set.of(
					PosixFilePermission.OWNER_READ,
					PosixFilePermission.OWNER_WRITE));
			}
			catch (UnsupportedOperationException ignored) {
				// Windows does not expose POSIX permissions.
			}
		}
		catch (IOException e) {
			throw new IllegalStateException("Could not save AETHER configuration to " + path(), e);
		}
	}

	public static String string(Map<String, Object> config, String key, String fallback) {
		Object value = config.get(key);
		return value instanceof String ? (String) value : fallback;
	}

	public static boolean bool(Map<String, Object> config, String key, boolean fallback) {
		Object value = config.get(key);
		return value instanceof Boolean ? (Boolean) value : fallback;
	}

	public static int integer(Map<String, Object> config, String key, int fallback) {
		Object value = config.get(key);
		return value instanceof Number ? ((Number) value).intValue() : fallback;
	}

	public static double decimal(Map<String, Object> config, String key, double fallback) {
		Object value = config.get(key);
		return value instanceof Number ? ((Number) value).doubleValue() : fallback;
	}
}
