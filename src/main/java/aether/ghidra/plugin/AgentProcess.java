package aether.ghidra.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import java.util.concurrent.TimeUnit;

import ghidra.util.Msg;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;

import aether.ghidra.bridge.BridgeServer;
import aether.ghidra.plugin.config.AetherConfigStore;
import aether.ghidra.bridge.Json;
import aether.ghidra.observability.DebugLog;

/** Starts and owns the bundled Python agent for the lifetime of the Ghidra plugin. */
public final class AgentProcess {
	private static final String DEFAULT_AGENT_URL = "http://127.0.0.1:8780";
	private static final String AGENT_PROCESS_MARKER = "aether_ghidra.api.server";
	private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
		.connectTimeout(Duration.ofMillis(200))
		.build();

	private Process process;
	private ProcessHandle adoptedProcess;
	private Path adoptedPidfile;
	private Thread shutdownHook;
	private boolean managed;
	private final ConsoleService consoleService;
	private final String configuredAgentUrl;

	public AgentProcess() {
		this(null, null);
	}

	public AgentProcess(PluginTool tool) {
		this(tool, null);
	}

	public AgentProcess(PluginTool tool, String agentUrl) {
		consoleService = tool == null ? null : tool.getService(ConsoleService.class);
		configuredAgentUrl = agentUrl == null || agentUrl.isBlank() ? null : agentUrl.replaceAll("/$", "");
	}

	public void start(int bridgePort) {
		DebugLog.debug(this, "starting Python agent bridge_port=" + bridgePort + " agent_url=" + agentUrl());
		sweepStaleAgents();
		if (isHealthy()) {
			adoptHealthyAgent();
			Msg.info(this, "Reusing the existing AETHER Python agent at " + agentUrl());
			return;
		}

		Path agentDirectory = resolveAgentDirectory();
		List<String> pythonCommand = resolvePythonCommand(agentDirectory);
		DebugLog.debug(this, "resolved agent_directory=" + agentDirectory + " python_command=" + pythonCommand);
		List<String> command = new ArrayList<>(pythonCommand);
		command.add("-m");
		command.add("aether_ghidra.api.server");
		ProcessBuilder builder = new ProcessBuilder(command);
		builder.directory(agentDirectory.toFile());
		builder.redirectErrorStream(true);
		Map<String, String> environment = builder.environment();
		environment.put("AETHER_GHIDRA_URL", "http://127.0.0.1:" + bridgePort);
		environment.put("AETHER_AGENT_URL", agentUrl());
		// Use exactly the same persisted configuration path as the GUI dialog.
		environment.put("AETHER_GHIDRA_CONFIG", AetherConfigStore.path().toString());
		configureAgentEndpoint(environment);
		environment.put("PYTHONUNBUFFERED", "1");
		String existingPythonPath = environment.get("PYTHONPATH");
		environment.put("PYTHONPATH", existingPythonPath == null || existingPythonPath.isBlank()
			? agentDirectory.toString()
			: agentDirectory + System.getProperty("path.separator") + existingPythonPath);

		try {
			process = builder.start();
			managed = true;
			installShutdownHook();
			startOutputLogger(process);
			waitForStartup();
		}
		catch (IOException e) {
			throw new IllegalStateException("Could not start the AETHER Python agent", e);
		}
	}

	public void stop() {
		if (!managed) {
			DebugLog.debug(this, "Python agent is not managed; nothing to stop");
			return;
		}
		DebugLog.debug(this, "stopping managed Python agent");
		if (process != null) {
			stopProcess(process);
		}
		else if (adoptedProcess != null) {
			stopProcess(adoptedProcess);
		}
		if (adoptedPidfile != null) {
			try {
				Files.deleteIfExists(adoptedPidfile);
			}
			catch (IOException e) {
				DebugLog.debug(this, "could not remove adopted agent pidfile: " + e.getMessage());
			}
		}
		managed = false;
		process = null;
		adoptedProcess = null;
		adoptedPidfile = null;
		removeShutdownHook();
	}

	void restart(int bridgePort) {
		if (!managed) {
			DebugLog.debug(this, "Python agent is externally managed; configuration will apply after restart");
			return;
		}
		stop();
		start(bridgePort);
	}

	boolean isManaged() {
		return managed && (process != null || adoptedProcess != null);
	}

	private void waitForStartup() {
		for (int attempt = 0; attempt < 100; attempt++) {
			if (isHealthy()) {
				Msg.info(this, "Started the AETHER Python agent at " + agentUrl());
				return;
			}
			if (process != null && !process.isAlive()) {
				throw new IllegalStateException("The AETHER Python agent exited during startup");
			}
			if (attempt % 10 == 0) {
				DebugLog.debug(this, "waiting for Python agent startup attempt=" + (attempt + 1));
			}
			try {
				Thread.sleep(100);
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IllegalStateException("Interrupted while starting the AETHER Python agent", e);
			}
		}
		throw new IllegalStateException("The AETHER Python agent did not become ready at " + agentUrl());
	}

	private boolean isHealthy() {
		return isHealthyAt(agentUrl());
	}

	static boolean isHealthyAt(String endpoint) {
		return isHealthyAt(endpoint, "aether-ghidra-agent");
	}

	private static boolean isHealthyAt(String endpoint, String service) {
		return readHealth(endpoint).map(body ->
			Boolean.TRUE.equals(body.get("ok")) && service.equals(body.get("service")) &&
			body.get("protocol_version") instanceof Number number &&
			number.intValue() == BridgeServer.PROTOCOL_VERSION).orElse(false);
	}

	private static java.util.Optional<Map<String, Object>> readHealth(String endpoint) {
		try {
			HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(endpoint + "/health"))
				.timeout(Duration.ofMillis(200))
				.GET()
				.build();
			HttpResponse<String> response = HTTP_CLIENT.send(request,
				HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() < 200 || response.statusCode() >= 300) {
				return java.util.Optional.empty();
			}
			return java.util.Optional.of(Json.object(Json.parse(response.body())));
		}
		catch (Exception e) {
			return java.util.Optional.empty();
		}
	}

	static boolean isPortInUse(String endpoint) {
		try {
			URI uri = URI.create(endpoint);
			if (uri.getHost() == null || uri.getPort() < 1) {
				return false;
			}
			try (Socket socket = new Socket()) {
				socket.connect(new InetSocketAddress(uri.getHost(), uri.getPort()), 200);
				return true;
			}
		}
		catch (Exception e) {
			return false;
		}
	}

	private String agentUrl() {
		if (configuredAgentUrl != null) {
			return configuredAgentUrl;
		}
		String configured = System.getenv("AETHER_AGENT_URL");
		return (configured == null || configured.isBlank() ? DEFAULT_AGENT_URL : configured)
			.replaceAll("/$", "");
	}

	private void adoptHealthyAgent() {
		Map<String, Object> health = readHealth(agentUrl()).orElse(null);
		if (health == null || !(health.get("pid") instanceof Number number)) {
			return;
		}
		Path pidfile = agentPidfilePath(agentUrl());
		Map<String, Object> metadata;
		try {
			if (!Files.isRegularFile(pidfile)) {
				return;
			}
			metadata = Json.object(Json.parse(Files.readString(pidfile)));
		}
		catch (Exception e) {
			return;
		}
		Object recordedPid = metadata.get("pid");
		if (!(recordedPid instanceof Number) || ((Number) recordedPid).longValue() != number.longValue()) {
			return;
		}
		adoptedProcess = ProcessHandle.of(number.longValue()).orElse(null);
		if (adoptedProcess != null && adoptedProcess.isAlive()) {
			adoptedPidfile = pidfile;
			managed = true;
			installShutdownHook();
		}
	}

	private static Path agentRunDirectory() {
		String configured = System.getenv("AETHER_AGENT_RUN_DIR");
		if (configured != null && !configured.isBlank()) {
			return Path.of(configured).toAbsolutePath().normalize();
		}
		return Path.of(System.getProperty("user.home"), ".config", "aether-ghidra", "run");
	}

	private static Path agentPidfilePath(String endpoint) {
		try {
			return agentRunDirectory().resolve("agent-" + URI.create(endpoint).getPort() + ".pid");
		}
		catch (IllegalArgumentException e) {
			return agentRunDirectory().resolve("agent-invalid.pid");
		}
	}

	private static void sweepStaleAgents() {
		Path directory = agentRunDirectory();
		if (!Files.isDirectory(directory)) {
			return;
		}
		try (Stream<Path> paths = Files.list(directory)) {
			paths.filter(path -> path.getFileName().toString().startsWith("agent-") &&
				path.getFileName().toString().endsWith(".pid"))
				.forEach(AgentProcess::sweepPidfile);
		}
		catch (IOException e) {
			DebugLog.debug(AgentProcess.class, "could not scan agent pidfiles: " + e.getMessage());
		}
	}

	private static void sweepPidfile(Path pidfile) {
		Map<String, Object> metadata;
		try {
			metadata = Json.object(Json.parse(Files.readString(pidfile)));
		}
		catch (Exception e) {
			return;
		}
		if (!(metadata.get("pid") instanceof Number pidNumber) ||
			!(metadata.get("agent_url") instanceof String agentEndpoint)) {
			return;
		}
		ProcessHandle handle = ProcessHandle.of(pidNumber.longValue()).orElse(null);
		if (handle == null || !handle.isAlive()) {
			try {
				Files.deleteIfExists(pidfile);
			}
			catch (IOException ignored) {
				// A later sweep can remove an inaccessible stale pidfile.
			}
			return;
		}
		String commandLine = handle.info().commandLine().orElse("");
		if (!commandLine.contains(AGENT_PROCESS_MARKER)) {
			return;
		}
		Map<String, Object> health = readHealth(agentEndpoint).orElse(null);
		if (health == null || !(health.get("pid") instanceof Number healthPid) ||
			healthPid.longValue() != pidNumber.longValue()) {
			return;
		}
		String bridgeEndpoint = metadata.get("bridge_url") instanceof String value ? value : "";
		if (bridgeEndpoint.isBlank() || isHealthyAt(bridgeEndpoint, "ghidra-aether-bridge")) {
			return;
		}
		DebugLog.debug(AgentProcess.class, "stopping stale agent pid=" + pidNumber +
			" with unavailable bridge=" + bridgeEndpoint);
		handle.destroy();
		try {
			handle.onExit().get(2, TimeUnit.SECONDS);
		}
		catch (Exception e) {
			if (handle.isAlive()) {
				handle.destroyForcibly();
			}
		}
	}

	private void installShutdownHook() {
		if (shutdownHook != null) {
			return;
		}
		shutdownHook = new Thread(this::stop, "aether-python-agent-shutdown");
		shutdownHook.setDaemon(true);
		Runtime.getRuntime().addShutdownHook(shutdownHook);
	}

	private void removeShutdownHook() {
		Thread hook = shutdownHook;
		shutdownHook = null;
		if (hook == null || hook == Thread.currentThread()) {
			return;
		}
		try {
			Runtime.getRuntime().removeShutdownHook(hook);
		}
		catch (IllegalStateException ignored) {
			// The JVM is already shutting down.
		}
	}

	private static void stopProcess(Process process) {
		process.destroy();
		try {
			if (!process.waitFor(3, TimeUnit.SECONDS)) {
				process.destroyForcibly();
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			process.destroyForcibly();
		}
	}

	private static void stopProcess(ProcessHandle process) {
		process.destroy();
		try {
			process.onExit().get(3, TimeUnit.SECONDS);
		}
		catch (Exception e) {
			if (process.isAlive()) {
				process.destroyForcibly();
			}
		}
	}

	private void configureAgentEndpoint(Map<String, String> environment) {
		try {
			URI endpoint = URI.create(agentUrl());
			if (endpoint.getHost() != null) {
				environment.put("AETHER_AGENT_HOST", endpoint.getHost());
			}
			if (endpoint.getPort() > 0) {
				environment.put("AETHER_AGENT_PORT", Integer.toString(endpoint.getPort()));
			}
		}
		catch (IllegalArgumentException error) {
			throw new IllegalStateException("Invalid AETHER_AGENT_URL: " + agentUrl(), error);
		}
	}

	private static Path resolveAgentDirectory() {
		String configured = System.getenv("AETHER_AGENT_DIR");
		if (configured != null && !configured.isBlank()) {
			return requireAgentDirectory(Path.of(configured));
		}

		try {
			Path codeLocation = Path.of(AetherPlugin.class.getProtectionDomain()
				.getCodeSource().getLocation().toURI());
			Path current = Files.isRegularFile(codeLocation) ? codeLocation.getParent() : codeLocation;
			while (current != null) {
				Path candidate = current.resolve("agent");
				if (Files.isDirectory(candidate.resolve("aether_ghidra"))) {
					return candidate;
				}
				current = current.getParent();
			}
		}
		catch (Exception e) {
			throw new IllegalStateException("Could not locate the bundled AETHER Python agent", e);
		}
		throw new IllegalStateException(
			"Bundled AETHER Python agent was not found; set AETHER_AGENT_DIR to its directory");
	}

	private static Path requireAgentDirectory(Path directory) {
		if (!Files.isDirectory(directory.resolve("aether_ghidra"))) {
			throw new IllegalStateException("AETHER_AGENT_DIR is not a Python agent directory: " + directory);
		}
		return directory;
	}

	private static List<String> resolvePythonCommand(Path agentDirectory) {
		String configured = System.getenv("AETHER_AGENT_PYTHON");
		if (configured != null && !configured.isBlank()) {
			return List.of(configured);
		}

		List<String> candidates = new ArrayList<>();
		if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
			candidates.add(agentDirectory.resolve(".venv/Scripts/python.exe").toString());
		}
		else {
			candidates.add(agentDirectory.resolve(".venv/bin/python").toString());
		}
		for (String candidate : candidates) {
			try {
				Process check = new ProcessBuilder(candidate, "--version")
					.redirectError(ProcessBuilder.Redirect.DISCARD)
					.redirectOutput(ProcessBuilder.Redirect.DISCARD)
					.start();
				if (check.waitFor(2, TimeUnit.SECONDS) && check.exitValue() == 0) {
					return List.of(candidate);
				}
			}
			catch (IOException | InterruptedException e) {
				if (e instanceof InterruptedException) {
					Thread.currentThread().interrupt();
				}
			}
		}
		String uv = findExecutable("uv");
		if (uv != null) {
			return List.of(uv, "run", "--project", agentDirectory.toString(), "--", "python");
		}
		candidates.add(System.getProperty("os.name", "").toLowerCase().contains("win") ? "python" : "python3");
		candidates.add("python");
		for (String candidate : candidates.subList(1, candidates.size())) {
			if (findExecutable(candidate) != null) {
				return List.of(candidate);
			}
		}
		throw new IllegalStateException(
			"Python was not found; install Python or set AETHER_AGENT_PYTHON");
	}

	private static String findExecutable(String executable) {
		try {
			Process check = new ProcessBuilder(executable, "--version")
				.redirectError(ProcessBuilder.Redirect.DISCARD)
				.redirectOutput(ProcessBuilder.Redirect.DISCARD)
				.start();
			if (check.waitFor(2, TimeUnit.SECONDS) && check.exitValue() == 0) {
				return executable;
			}
		}
		catch (IOException | InterruptedException e) {
			if (e instanceof InterruptedException) {
				Thread.currentThread().interrupt();
			}
		}
		return null;
	}

	private void startOutputLogger(Process agent) {
		Thread logger = new Thread(() -> {
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(
				agent.getInputStream(), StandardCharsets.UTF_8))) {
				String line;
				while ((line = reader.readLine()) != null) {
					String message = "[python-agent] " + line;
					Msg.info(AgentProcess.class, message);
					if (consoleService != null) {
						consoleService.println(message);
					}
				}
			}
			catch (IOException e) {
				Msg.warn(AgentProcess.class, "Could not read Python agent output: " + e.getMessage());
			}
		}, "aether-python-agent-output");
		logger.setDaemon(true);
		logger.start();
	}
}
