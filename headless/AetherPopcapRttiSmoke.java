import java.util.List;
import java.util.Map;

import aether.ghidra.bridge.Json;
import ghidra.app.script.GhidraScript;
import ghidra.framework.options.Options;

/** Verifies namespaced RTTI identity and direct-base extraction on PopCap RTTI. */
public class AetherPopcapRttiSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        Options options = currentProgram.getOptions("AETHER");
        String encoded = options.getString("rtti_analysis", null);
        if (encoded == null) {
            throw new IllegalStateException("AETHER RTTI analysis is missing");
        }
        Map<String, Object> document = Json.object(Json.parse(encoded));
        Map<String, Object> classes = Json.object(document.get("classes"));
        Map<String, Object> sexyImage = model(classes, "Sexy::Image");
        Map<String, Object> imageLibImage = model(classes, "ImageLib::Image");
        Map<String, Object> memoryImage = model(classes, "Sexy::MemoryImage");
        Map<String, Object> ddImage = model(classes, "Sexy::DDImage");

        require(sexyImage != imageLibImage, "Namespaced Image classes were merged");
        require(names(memoryImage).equals(List.of("Sexy::Image")),
            "MemoryImage direct base is incorrect: " + names(memoryImage));
        require(names(ddImage).equals(List.of("Sexy::MemoryImage")),
            "DDImage direct bases are incorrect: " + names(ddImage));
        println("AETHER_POPCAP_RTTI_SMOKE_OK");
    }

    private static Map<String, Object> model(Map<String, Object> classes, String name) {
        for (Object raw : classes.values()) {
            Map<String, Object> model = Json.object(raw);
            if (name.equals(model.get("name"))) {
                return model;
            }
        }
        throw new IllegalStateException("Missing RTTI class: " + name);
    }

    private static List<String> names(Map<String, Object> model) {
        return ((List<?>) model.getOrDefault("bases", List.of())).stream()
            .map(Json::object)
            .map(base -> String.valueOf(base.get("name")))
            .toList();
    }

    private static void require(boolean condition, String message) {
        if (!condition) {
            throw new IllegalStateException(message);
        }
    }
}
