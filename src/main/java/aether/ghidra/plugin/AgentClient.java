package aether.ghidra.plugin;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

import aether.ghidra.bridge.Json;
import aether.ghidra.observability.DebugLog;

/** Non-blocking-call target for the Python agent service. */
final class AgentClient {
	private static final String DEFAULT_URL = "http://127.0.0.1:8780";

	private final HttpClient httpClient;
	private final String baseUrl;

	AgentClient() {
		this(null);
	}

	AgentClient(String configuredUrl) {
		httpClient = HttpClient.newBuilder()
			.connectTimeout(Duration.ofSeconds(2))
			.build();
		String configured = configuredUrl == null ? System.getenv("AETHER_AGENT_URL") : configuredUrl;
		baseUrl = (configured == null || configured.isBlank() ? DEFAULT_URL : configured).replaceAll("/$", "");
	}

	@SuppressWarnings("unchecked")
	Map<String, Object> analyze(Map<String, Object> request) {
		DebugLog.debug(this, "sending analysis request to " + baseUrl + " program_id=" + request.get("program_id") +
			" address=" + request.get("address"));
		try {
			HttpRequest httpRequest = HttpRequest.newBuilder()
				.uri(URI.create(baseUrl + "/v1/analyze"))
				.timeout(Duration.ofSeconds(120))
				.header("Accept", "application/json")
				.header("Content-Type", "application/json")
				.POST(HttpRequest.BodyPublishers.ofString(Json.stringify(request)))
				.build();
			HttpResponse<String> response = sendWithRetry(httpRequest);
			if (response.statusCode() < 200 || response.statusCode() >= 300) {
				throw new IllegalStateException("Python agent returned HTTP " + response.statusCode() +
					": " + response.body());
			}
			Map<String, Object> decoded = Json.object(Json.parse(response.body()));
			DebugLog.debug(this, "received analysis response status=" + response.statusCode());
			if (!Boolean.TRUE.equals(decoded.get("ok"))) {
				throw new IllegalStateException("Python agent rejected the analysis request: " + response.body());
			}
			return (Map<String, Object>) decoded.get("result");
		}
		catch (Exception e) {
			DebugLog.debug(this, "analysis request failed: " + e.getClass().getSimpleName());
			throw new IllegalStateException("Python AETHER agent request failed at " + baseUrl + ": " + e.getMessage(), e);
		}
	}

	Map<String, Object> startAnnotation(Map<String, Object> request) {
		return agentRequest("POST", "/v1/annotation-jobs", request, Duration.ofSeconds(30));
	}

	Map<String, Object> annotationJob(String jobId) {
		return agentRequest("GET", "/v1/annotation-jobs/" + jobId, null, Duration.ofSeconds(30));
	}

	Map<String, Object> cancelAnnotation(String jobId) {
		return agentRequest("POST", "/v1/annotation-jobs/" + jobId + "/cancel", new LinkedHashMap<>(), Duration.ofSeconds(30));
	}

	Map<String, Object> undoAnnotation(String programId) {
		Map<String, Object> request = new LinkedHashMap<>();
		request.put("program_id", programId);
		return agentRequest("POST", "/v1/annotations/undo", request, Duration.ofSeconds(30));
	}

	Map<String, Object> annotationCandidates(String programId, Map<String, Object> address) {
		Map<String, Object> arguments = new LinkedHashMap<>();
		arguments.put("address", address);
		arguments.put("direction", "callees");
		arguments.put("max_depth", 5);
		arguments.put("max_functions", 30);
		arguments.put("max_edges", 48);
		Map<String, Object> request = new LinkedHashMap<>();
		request.put("program_id", programId);
		request.put("capability", "get_function_call_tree");
		request.put("arguments", arguments);
		return agentRequest("POST", "/v1/invoke", request, Duration.ofSeconds(30));
	}

	Map<String, Object> startChat(String programId, String message, Map<String, Object> address) {
		Map<String, Object> request = new LinkedHashMap<>();
		request.put("program_id", programId);
		request.put("message", message);
		if (address != null) {
			request.put("address", address);
		}
		return agentRequest("POST", "/v1/chat-jobs", request, Duration.ofSeconds(30));
	}

	Map<String, Object> chatJob(String jobId) {
		return agentRequest("GET", "/v1/chat-jobs/" + jobId, null, Duration.ofSeconds(30));
	}

	Map<String, Object> cancelChat(String jobId) {
		return agentRequest("POST", "/v1/chat-jobs/" + jobId + "/cancel", new LinkedHashMap<>(), Duration.ofSeconds(30));
	}

	Map<String, Object> sessionState(String programId) {
		return agentRequest("GET", "/v1/session/" + programId, null, Duration.ofSeconds(30));
	}

	void clearSession(String programId) {
		agentRequest("POST", "/v1/session/clear", Map.of("program_id", programId), Duration.ofSeconds(30));
	}

	Map<String, Object> startIndex(String programId, boolean resume, boolean reindex) {
		Map<String, Object> request = new LinkedHashMap<>();
		request.put("program_id", programId);
		request.put("resume", resume);
		request.put("reindex", reindex);
		return agentRequest("POST", "/v1/index-jobs", request, Duration.ofSeconds(30));
	}

	Map<String, Object> indexJob(String jobId) {
		return agentRequest("GET", "/v1/index-jobs/" + jobId, null, Duration.ofSeconds(30));
	}

	Map<String, Object> cancelIndex(String jobId) {
		return agentRequest("POST", "/v1/index-jobs/" + jobId + "/cancel", new LinkedHashMap<>(), Duration.ofSeconds(30));
	}

	Map<String, Object> indexStats(String programId) {
		return agentRequest("POST", "/v1/index-stats", Map.of("program_id", programId), Duration.ofSeconds(30));
	}

	Map<String, Object> indexEntries(String programId) {
		return agentRequest("POST", "/v1/index-entries", Map.of(
			"program_id", programId, "offset", 0, "limit", 5000), Duration.ofSeconds(30));
	}

	@SuppressWarnings("unchecked")
	private Map<String, Object> agentRequest(String method, String path, Map<String, Object> payload,
		Duration timeout) {
		try {
			HttpRequest.Builder builder = HttpRequest.newBuilder()
				.uri(URI.create(baseUrl + path))
				.timeout(timeout)
				.header("Accept", "application/json");
			if (payload == null) {
				builder.method(method, HttpRequest.BodyPublishers.noBody());
			}
			else {
				builder.header("Content-Type", "application/json")
					.method(method, HttpRequest.BodyPublishers.ofString(Json.stringify(payload)));
			}
			HttpResponse<String> response = sendWithRetry(builder.build());
			if (response.statusCode() < 200 || response.statusCode() >= 300) {
				throw new IllegalStateException("Python agent returned HTTP " + response.statusCode() + ": " + response.body());
			}
			Map<String, Object> decoded = Json.object(Json.parse(response.body()));
			if (!Boolean.TRUE.equals(decoded.get("ok"))) {
				throw new IllegalStateException("Python agent rejected the request: " + response.body());
			}
			Object result = decoded.get("result");
			return result instanceof Map<?, ?> ? (Map<String, Object>) result : decoded;
		}
		catch (Exception e) {
			throw new IllegalStateException("Python AETHER agent request failed at " + baseUrl + ": " + e.getMessage(), e);
		}
	}

	private HttpResponse<String> sendWithRetry(HttpRequest request)
		throws IOException, InterruptedException {
		IOException lastFailure = null;
		for (int attempt = 0; attempt < 5; attempt++) {
			try {
				return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
			}
			catch (IOException e) {
				lastFailure = e;
				if (attempt == 4) {
					throw e;
				}
				DebugLog.debug(this, "Python agent connection failed; retry=" + (attempt + 1));
				Thread.sleep(250L * (attempt + 1));
			}
		}
		throw lastFailure == null ? new IOException("Python agent request failed") : lastFailure;
	}
}
