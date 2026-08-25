package aether.ghidra.plugin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
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
	private static final HttpClient HTTP_CLIENT = HttpClient.newBuilder()
		.connectTimeout(Duration.ofMillis(200))
		.build();

	private Process process;
	private boolean managed;
	private final ConsoleService consoleService;

	public AgentProcess() {
		consoleService = null;
	}

	public AgentProcess(PluginTool tool) {
		consoleService = tool == null ? null : tool.getService(ConsoleService.class);
	}

	public void start(int bridgePort) {
		DebugLog.debug(this, "starting Python agent bridge_port=" + bridgePort + " agent_url=" + agentUrl());
		if (isHealthy()) {
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
			startOutputLogger(process);
			waitForStartup();
		}
		catch (IOException e) {
			throw new IllegalStateException("Could not start the AETHER Python agent", e);
		}
	}

	public void stop() {
		if (!managed || process == null) {
			DebugLog.debug(this, "Python agent is not managed; nothing to stop");
			return;
		}
		process.destroy();
		DebugLog.debug(this, "stopping managed Python agent");
		try {
			if (!process.waitFor(3, TimeUnit.SECONDS)) {
				process.destroyForcibly();
			}
		}
		catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			process.destroyForcibly();
		}
		managed = false;
		process = null;
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
		return managed && process != null;
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
		try {
			HttpRequest request = HttpRequest.newBuilder()
				.uri(URI.create(agentUrl() + "/health"))
				.timeout(Duration.ofMillis(200))
				.GET()
				.build();
			HttpResponse<String> response = HTTP_CLIENT.send(request,
				HttpResponse.BodyHandlers.ofString());
			if (response.statusCode() < 200 || response.statusCode() >= 300) {
				return false;
			}
			Map<String, Object> body = Json.object(Json.parse(response.body()));
			Object protocolVersion = body.get("protocol_version");
			return Boolean.TRUE.equals(body.get("ok")) &&
				"aether-ghidra-agent".equals(body.get("service")) &&
				protocolVersion instanceof Number number && number.intValue() == BridgeServer.PROTOCOL_VERSION;
		}
		catch (Exception e) {
			return false;
		}
	}

	private static String agentUrl() {
		String configured = System.getenv("AETHER_AGENT_URL");
		return (configured == null || configured.isBlank() ? DEFAULT_AGENT_URL : configured)
			.replaceAll("/$", "");
	}

	private static void configureAgentEndpoint(Map<String, String> environment) {
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
