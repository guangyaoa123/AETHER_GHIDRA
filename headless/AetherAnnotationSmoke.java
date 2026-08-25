import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import aether.ghidra.headless.HeadlessAetherRuntime;
import aether.ghidra.program.ProgramRegistry;

/** Headless smoke test for the installed AETHER bridge and annotation batch. */
public class AetherAnnotationSmoke extends GhidraScript {
    private static final Pattern PROGRAM_ID = Pattern.compile("\\\"program_id\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
    private final HttpClient client = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(2))
        .build();

    @Override
    public void run() throws Exception {
        require(currentProgram != null, "AETHER headless smoke test requires an imported current Program");
        String baseUrl = System.getenv().getOrDefault("AETHER_GHIDRA_URL", "http://127.0.0.1:8875");
        int bridgePort = integerEnvironment("AETHER_GHIDRA_PORT", 8875);
        try (HeadlessAetherRuntime runtime = new HeadlessAetherRuntime(currentProgram, bridgePort)) {
            runtime.start();
            waitForHealth(baseUrl);

            String programs = get(baseUrl + "/v1/programs");
            Matcher programMatcher = PROGRAM_ID.matcher(programs);
            require(programMatcher.find(), "No registered Program was returned by the AETHER bridge");
            String programId = programMatcher.group(1);

            Function function = firstFunction();
            Map<String, Object> address = ProgramRegistry.addressMap(function.getEntryPoint());
            String addressJson = "{\"space\":\"" + address.get("space") + "\",\"offset\":\"" + address.get("offset") + "\"}";

            String tree = invoke(baseUrl, programId, "get_function_call_tree",
                "{\"address\":" + addressJson + ",\"direction\":\"callees\",\"max_depth\":1,\"max_functions\":8,\"max_edges\":16}");
            require(tree.contains("\"functions\""), "Call-tree capability returned no functions");
            String context = invoke(baseUrl, programId, "get_annotation_context",
                "{\"functions\":[{\"address\":" + addressJson + "}]}");
            require(context.contains("\"pseudocode\":\"0x"),
                "Annotation context did not contain address-annotated pseudocode");

            String originalComment = function.getComment() == null ? "" : function.getComment();
            String smokeComment = "AETHER headless annotation smoke test";
            String operation = "{\"id\":\"headless-smoke\",\"kind\":\"set_function_comment\","
                + "\"target\":{\"function_address\":" + addressJson + "},"
                + "\"expected_before\":\"" + jsonEscape(originalComment) + "\","
                + "\"value\":\"" + jsonEscape(smokeComment) + "\"}";
            String applied = invoke(baseUrl, programId, "apply_annotation_batch", "{\"operations\":[" + operation + "]}");
            require(applied.contains("\"batch_id\""), "Annotation batch did not return a batch_id");
            require(smokeComment.equals(function.getComment()), "Ghidra function comment was not applied");

            String inverse = "{\"id\":\"headless-smoke-undo\",\"kind\":\"set_function_comment\","
                + "\"target\":{\"function_address\":" + addressJson + "},"
                + "\"expected_before\":\"" + jsonEscape(smokeComment) + "\","
                + "\"value\":\"" + jsonEscape(originalComment) + "\"}";
            invoke(baseUrl, programId, "apply_annotation_batch", "{\"operations\":[" + inverse + "]}");
            require(originalComment.equals(function.getComment() == null ? "" : function.getComment()),
                "Headless smoke test could not restore the original comment");

            println("AETHER_HEADLESS_ANNOTATION_SMOKE_OK");
            println("program_id=" + programId + " function=" + function.getName() + " address=" + address);
        }
    }

    private Function firstFunction() {
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        require(functions.hasNext(), "Imported Program contains no functions");
        return functions.next();
    }

    private void waitForHealth(String baseUrl) throws Exception {
        for (int attempt = 0; attempt < 60; attempt++) {
            try {
                if (get(baseUrl + "/health").contains("\"ok\":true")) {
                    return;
                }
            }
            catch (Exception ignored) {
                // The plugin starts the bridge during initialization.
            }
            Thread.sleep(250);
        }
        throw new IllegalStateException("AETHER bridge did not become healthy at " + baseUrl);
    }

    private String invoke(String baseUrl, String programId, String capability, String arguments) throws Exception {
        String payload = "{\"program_id\":\"" + jsonEscape(programId) + "\",\"capability\":\""
            + capability + "\",\"arguments\":" + arguments + "}";
        return post(baseUrl + "/v1/invoke", payload);
    }

    private String get(String url) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(5)).GET().build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        require(response.statusCode() >= 200 && response.statusCode() < 300,
            "GET " + url + " returned HTTP " + response.statusCode() + ": " + response.body());
        return response.body();
    }

    private String post(String url, String payload) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create(url))
            .timeout(Duration.ofSeconds(10))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(payload))
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        require(response.statusCode() >= 200 && response.statusCode() < 300,
            "POST " + url + " returned HTTP " + response.statusCode() + ": " + response.body());
        return response.body();
    }

    private static String jsonEscape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }

    private static int integerEnvironment(String name, int fallback) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value);
        }
        catch (NumberFormatException error) {
            throw new IllegalArgumentException(name + " must be an integer", error);
        }
    }
}
