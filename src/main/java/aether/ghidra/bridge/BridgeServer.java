package aether.ghidra.bridge;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Executors;

import ghidra.util.Msg;

import aether.ghidra.observability.DebugLog;
import aether.ghidra.program.ProgramRegistry;
import ghidra.program.model.listing.Program;

/** Localhost-only HTTP bridge used by the Python agent service. */
public final class BridgeServer {
	private static final int MAX_BODY_BYTES = 1024 * 1024;
	public static final int PROTOCOL_VERSION = 2;

	private final ProgramRegistry registry;
	private final int requestedPort;
	private HttpServer server;

	public BridgeServer(ProgramRegistry registry, int requestedPort) {
		this.registry = registry;
		this.requestedPort = requestedPort;
	}

	public void start() {
		DebugLog.debug(this, "starting localhost bridge requested_port=" + requestedPort);
		try {
			server = HttpServer.create(new InetSocketAddress("127.0.0.1", requestedPort), 0);
			server.createContext("/health", this::handleHealth);
			server.createContext("/v1/programs", this::handlePrograms);
			server.createContext("/v1/project", this::handleProject);
			server.createContext("/v1/programs/open", this::handleOpenProgram);
			server.createContext("/v1/programs/close", this::handleCloseProgram);
			server.createContext("/v1/invoke", this::handleInvoke);
			server.createContext("/v1/import", this::handleImport);
			server.setExecutor(Executors.newCachedThreadPool(runnable -> {
				Thread thread = new Thread(runnable, "aether-ghidra-bridge");
				thread.setDaemon(true);
				return thread;
			}));
			server.start();
		}
		catch (IOException e) {
			throw new IllegalStateException("Could not start AETHER bridge on port " + requestedPort, e);
		}
	}

	private void handleProject(HttpExchange exchange) throws IOException {
		if (!method(exchange, "GET")) {
			return;
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("project", registry.projectMetadata());
		writeJson(exchange, 200, result);
	}

	private void handleOpenProgram(HttpExchange exchange) throws IOException {
		handleProgramLifecycle(exchange, true);
	}

	private void handleCloseProgram(HttpExchange exchange) throws IOException {
		handleProgramLifecycle(exchange, false);
	}

	private void handleProgramLifecycle(HttpExchange exchange, boolean open) throws IOException {
		if (!method(exchange, "POST")) {
			return;
		}
		try {
			Map<String, Object> request = Json.object(readJson(exchange));
			Object requestVersion = request.get("protocol_version");
			if (!(requestVersion instanceof Number number) || number.intValue() != PROTOCOL_VERSION) {
				throw new ProgramRegistry.BridgeException("protocol_mismatch",
					"Unsupported bridge protocol version: " + requestVersion);
			}
			String programId = Json.string(request, "program_id");
			Map<String, Object> response = new LinkedHashMap<>();
			response.put("ok", true);
			response.put("protocol_version", PROTOCOL_VERSION);
			response.put("result", open ? registry.openProgram(programId) : registry.closeProgram(programId));
			writeJson(exchange, 200, response);
		}
		catch (ProgramRegistry.BridgeException error) {
			writeError(exchange, 400, error.code(), error.getMessage());
		}
		catch (Exception error) {
			Msg.error(this, "AETHER Program lifecycle request failed", error);
			writeError(exchange, 500, "internal_error", error.getMessage());
		}
	}

	public void stop() {
		if (server != null) {
			DebugLog.debug(this, "stopping bridge port=" + server.getAddress().getPort());
			server.stop(1);
			server = null;
		}
	}

	/** Registers a Program opened by another GUI tool in the shared bridge registry. */
	public void registerProgram(Program program) {
		registry.register(program);
	}

	/** Removes a Program closed by another GUI tool from the shared bridge registry. */
	public void unregisterProgram(Program program) {
		registry.unregister(program);
	}

	public int getPort() {
		return server == null ? requestedPort : server.getAddress().getPort();
	}

	private void handleHealth(HttpExchange exchange) throws IOException {
		if (!method(exchange, "GET")) {
			return;
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("ok", true);
		result.put("service", "ghidra-aether-bridge");
		result.put("protocol_version", PROTOCOL_VERSION);
		writeJson(exchange, 200, result);
	}

	private void handlePrograms(HttpExchange exchange) throws IOException {
		if (!method(exchange, "GET")) {
			return;
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("programs", registry.listPrograms());
		writeJson(exchange, 200, result);
	}

	private void handleInvoke(HttpExchange exchange) throws IOException {
		if (!method(exchange, "POST")) {
			return;
		}
		try {
			Map<String, Object> request = Json.object(readJson(exchange));
			Object requestVersion = request.get("protocol_version");
			if (!(requestVersion instanceof Number number) || number.intValue() != PROTOCOL_VERSION) {
				throw new ProgramRegistry.BridgeException("protocol_mismatch",
					"Unsupported bridge protocol version: " + requestVersion);
			}
			String programId = Json.string(request, "program_id");
			String capability = Json.string(request, "capability");
			DebugLog.debug(this, "bridge invoke program_id=" + programId + " capability=" + capability);
			Map<String, Object> arguments = Json.optionalObject(request, "arguments");
			Map<String, Object> response = new LinkedHashMap<>();
			response.put("ok", true);
			response.put("protocol_version", PROTOCOL_VERSION);
			response.put("result", registry.invoke(programId, capability, arguments));
			writeJson(exchange, 200, response);
		}
		catch (ProgramRegistry.BridgeException e) {
			DebugLog.debug(this, "bridge invoke rejected code=" + e.code());
			writeError(exchange, 400, e.code(), e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this, "AETHER bridge request failed", e);
			writeError(exchange, 500, "internal_error", e.getMessage());
		}
	}

	private void handleImport(HttpExchange exchange) throws IOException {
		if (!method(exchange, "POST")) {
			return;
		}
		try {
			Map<String, Object> request = Json.object(readJson(exchange));
			Object requestVersion = request.get("protocol_version");
			if (!(requestVersion instanceof Number number) || number.intValue() != PROTOCOL_VERSION) {
				throw new ProgramRegistry.BridgeException("protocol_mismatch",
					"Unsupported bridge protocol version: " + requestVersion);
			}
			String path = importPath(request);
			DebugLog.debug(this, "bridge import path=" + path);
			Map<String, Object> response = new LinkedHashMap<>();
			response.put("ok", true);
			response.put("protocol_version", PROTOCOL_VERSION);
			response.put("result", registry.importProgram(new java.io.File(path)));
			writeJson(exchange, 200, response);
		}
		catch (ProgramRegistry.BridgeException e) {
			DebugLog.debug(this, "bridge import rejected code=" + e.code());
			writeError(exchange, 400, e.code(), e.getMessage());
		}
		catch (IllegalArgumentException e) {
			writeError(exchange, 400, "invalid_argument", e.getMessage());
		}
		catch (Exception e) {
			Msg.error(this, "AETHER bridge import failed", e);
			writeError(exchange, 500, "internal_error", e.getMessage());
		}
	}

	private static String importPath(Map<String, Object> request) {
		Object value = request.get("path");
		if (value == null) {
			value = request.get("file_path");
		}
		if (value == null) {
			value = request.get("file");
		}
		if (!(value instanceof String path) || path.isBlank()) {
			throw new ProgramRegistry.BridgeException("invalid_argument", "path is required");
		}
		return path;
	}

	private static boolean method(HttpExchange exchange, String expected) throws IOException {
		if (expected.equals(exchange.getRequestMethod())) {
			return true;
		}
		writeError(exchange, 405, "method_not_allowed", "Expected " + expected);
		return false;
	}

	private static Object readJson(HttpExchange exchange) throws IOException {
		try (InputStream input = exchange.getRequestBody()) {
			byte[] body = input.readNBytes(MAX_BODY_BYTES + 1);
			if (body.length > MAX_BODY_BYTES) {
				throw new ProgramRegistry.BridgeException("request_too_large", "Request body is too large");
			}
			return Json.parse(new String(body, StandardCharsets.UTF_8));
		}
		catch (IllegalArgumentException e) {
			throw new ProgramRegistry.BridgeException("invalid_json", e.getMessage(), e);
		}
	}

	private static void writeError(HttpExchange exchange, int status, String code, String message)
		throws IOException {
		Map<String, Object> error = new LinkedHashMap<>();
		error.put("code", code);
		error.put("message", message == null ? "" : message);
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("ok", false);
		response.put("error", error);
		writeJson(exchange, status, response);
	}

	private static void writeJson(HttpExchange exchange, int status, Map<String, Object> value)
		throws IOException {
		byte[] body = Json.stringify(value).getBytes(StandardCharsets.UTF_8);
		Headers headers = exchange.getResponseHeaders();
		headers.set("Content-Type", "application/json; charset=utf-8");
		headers.set("Cache-Control", "no-store");
		exchange.sendResponseHeaders(status, body.length);
		try (OutputStream output = exchange.getResponseBody()) {
			output.write(body);
		}
	}
}
