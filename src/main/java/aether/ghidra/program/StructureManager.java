package aether.ghidra.program;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.framework.options.Options;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.data.DataTypeParser;

import aether.ghidra.bridge.Json;

/** Native Ghidra structure operations plus the small amount of class metadata Ghidra cannot model. */
final class StructureManager {
	private static final String OPTIONS_NAME = "AETHER";
	private static final String CLASS_MODELS = "struct_class_models";
	private static final String DEFAULT_CATEGORY = "/AETHER/Types";

	private StructureManager() {
	}

	static Map<String, Object> invoke(Program program, String capability, Map<String, Object> arguments) {
		return switch (capability) {
			case "list_struct" -> listStruct(program, arguments);
			case "get_struct" -> getStruct(program, arguments);
			case "create_struct" -> createStruct(program, arguments);
			case "add_fields" -> addFields(program, arguments);
			case "update_fields" -> updateFields(program, arguments);
			case "remove_fields" -> removeFields(program, arguments);
			case "resize_struct" -> resizeStruct(program, arguments);
			case "create_class" -> createClass(program, arguments);
			case "update_class" -> updateClass(program, arguments);
			case "delete_class" -> deleteClass(program, arguments);
			default -> throw new ProgramRegistry.BridgeException("capability_unsupported",
				"Unsupported structure capability: " + capability);
		};
	}

	private static Map<String, Object> listStruct(Program program, Map<String, Object> arguments) {
		String pattern = optionalString(arguments, "pattern");
		Pattern namePattern = null;
		if (pattern != null && !pattern.isBlank()) {
			try {
				namePattern = Pattern.compile(pattern, Pattern.CASE_INSENSITIVE);
			}
			catch (PatternSyntaxException e) {
				throw invalid("Invalid structure pattern: " + e.getMessage());
			}
		}
		String kind = optionalString(arguments, "kind");
		boolean groupedClasses = Boolean.TRUE.equals(arguments.get("grouped"));
		int limit = integer(arguments, "limit", 100);
		if (limit < 1 || limit > 1000) {
			throw invalid("limit must be between 1 and 1000");
		}
		Map<String, Map<String, Object>> models = allClassModels(program);
		List<Structure> structures = new ArrayList<>();
		Iterator<Structure> iterator = program.getDataTypeManager().getAllStructures();
		while (iterator.hasNext()) {
			structures.add(iterator.next());
		}
		structures.sort(Comparator.comparing(DataType::getPathName));
		List<Map<String, Object>> result = new ArrayList<>();
		for (Structure structure : structures) {
			Map<String, Object> item = structureSummary(program, structure, models);
			if (kind != null && !kind.equals(item.get("kind"))) {
				continue;
			}
			if (groupedClasses && "class".equals(kind) && !isClassGroupRoot(program, structure, models)) {
				continue;
			}
			if (namePattern != null && !namePattern.matcher(String.valueOf(item.get("path"))).find()) {
				continue;
			}
			result.add(item);
			if (result.size() >= limit) {
				break;
			}
		}
		Map<String, Object> response = new LinkedHashMap<>();
		response.put("structures", result);
		response.put("total", result.size());
		response.put("truncated", result.size() >= limit && structures.size() > result.size());
		return response;
	}

	private static Map<String, Object> getStruct(Program program, Map<String, Object> arguments) {
		Structure structure = resolveStructure(program, arguments);
		Map<String, Map<String, Object>> models = allClassModels(program);
		Map<String, Object> result = structureSummary(program, structure, models);
		List<Map<String, Object>> fields = new ArrayList<>();
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			Map<String, Object> field = new LinkedHashMap<>();
			field.put("ordinal", component.getOrdinal());
			field.put("offset", component.getOffset());
			field.put("length", component.getLength());
			field.put("name", component.getFieldName());
			field.put("data_type", component.getDataType().getDisplayName());
			field.put("data_type_path", component.getDataType().getPathName());
			field.put("comment", component.getComment() == null ? "" : component.getComment());
			fields.add(field);
		}
		result.put("fields", fields);
		Map<String, Object> model = classModelFor(program, structure, models);
		if (model != null) {
			result.put("class", classDetails(program, structure, model, models));
		}
		return result;
	}

	private static Map<String, Object> createStruct(Program program, Map<String, Object> arguments) {
		String name = required(arguments, "name");
		CategoryPath category = category(arguments);
		if (program.getDataTypeManager().getDataType(category, name) != null) {
			throw new ProgramRegistry.BridgeException("already_exists", "Structure already exists: " + category.getPath() + "/" + name);
		}
		List<Map<String, Object>> fields = fields(arguments);
		int requestedLength = integer(arguments, "size", integer(arguments, "length", 0));
		if (requestedLength < 0) {
			throw invalid("size must not be negative");
		}
		int length = Math.max(requestedLength, requiredFieldEnd(program, fields));
		int transaction = program.startTransaction("AETHER: create structure");
		boolean commit = false;
		try {
			StructureDataType requested = new StructureDataType(category, name, 0,
				program.getDataTypeManager());
			Structure structure = (Structure) program.getDataTypeManager().addDataType(
				requested, DataTypeConflictHandler.DEFAULT_HANDLER);
			applyAddedFields(program, structure, fields);
			if (structure.getLength() < length) {
				structure.setLength(length);
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", category.getPath() + "/" + name));
	}

	private static Map<String, Object> addFields(Program program, Map<String, Object> arguments) {
		Structure structure = resolveStructure(program, arguments);
		List<Map<String, Object>> fields = fields(arguments);
		if (fields.isEmpty()) {
			throw invalid("fields must not be empty");
		}
		int transaction = program.startTransaction("AETHER: add structure fields");
		boolean commit = false;
		try {
			validateNewFields(program, structure, fields, Set.of());
			applyAddedFields(program, structure, fields);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", structure.getPathName()));
	}

	private static Map<String, Object> updateFields(Program program, Map<String, Object> arguments) {
		Structure structure = resolveStructure(program, arguments);
		List<Map<String, Object>> fields = fields(arguments);
		if (fields.isEmpty()) {
			throw invalid("fields must not be empty");
		}
		int transaction = program.startTransaction("AETHER: update structure fields");
		boolean commit = false;
		try {
			Set<Integer> updatedOffsets = new HashSet<>();
			for (Map<String, Object> field : fields) {
				int offset = integer(field, "offset", -1);
				if (offset < 0 || !updatedOffsets.add(offset)) {
					throw invalid("Each updated field must have a unique non-negative offset");
				}
				DataTypeComponent component = definedComponentAt(structure, offset);
				if (component == null) {
					continue;
				}
				if (field.containsKey("data_type") || field.containsKey("length")) {
					DataType type = field.containsKey("data_type")
						? parseDataType(program, required(field, "data_type")) : component.getDataType();
					int length = integer(field, "length", component.getLength());
					validateReplacement(structure, component, offset, length);
					structure.replaceAtOffset(offset, type, length,
						optionalString(field, "name", component.getFieldName()),
						optionalString(field, "comment", component.getComment()));
				}
				else {
					String name = optionalString(field, "name");
					String comment = optionalString(field, "comment");
					if (name != null) {
						component.setFieldName(name);
					}
					if (comment != null) {
						component.setComment(comment);
					}
				}
			}
			List<Map<String, Object>> missing = new ArrayList<>();
			for (Map<String, Object> field : fields) {
				int offset = integer(field, "offset", -1);
				if (definedComponentAt(structure, offset) == null) {
					missing.add(field);
				}
			}
			validateNewFields(program, structure, missing, updatedOffsets);
			applyAddedFields(program, structure, missing);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", structure.getPathName()));
	}

	private static Map<String, Object> removeFields(Program program, Map<String, Object> arguments) {
		Structure structure = resolveStructure(program, arguments);
		List<Integer> offsets = new ArrayList<>();
		Object rawOffsets = arguments.get("offsets");
		if (rawOffsets instanceof List<?> list) {
			for (Object value : list) {
				offsets.add(asInteger(value, "offset"));
			}
		}
		for (Map<String, Object> field : fields(arguments)) {
			offsets.add(integer(field, "offset", -1));
		}
		if (offsets.isEmpty() || offsets.stream().anyMatch(offset -> offset < 0)) {
			throw invalid("offsets or fields with offsets are required");
		}
		int transaction = program.startTransaction("AETHER: remove structure fields");
		boolean commit = false;
		try {
			for (int offset : offsets) {
				if (definedComponentAt(structure, offset) == null) {
					throw new ProgramRegistry.BridgeException("not_found", "No defined field at offset 0x" + Integer.toHexString(offset));
				}
			}
			for (int offset : offsets) {
				structure.deleteAtOffset(offset);
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", structure.getPathName()));
	}

	private static Map<String, Object> resizeStruct(Program program, Map<String, Object> arguments) {
		Structure structure = resolveStructure(program, arguments);
		int length = integer(arguments, "size", integer(arguments, "length", -1));
		if (length < 0) {
			throw invalid("size or length must be a non-negative integer");
		}
		if (length < structure.getLength()) {
			for (DataTypeComponent component : structure.getDefinedComponents()) {
				if (component.getEndOffset() >= length) {
					throw invalid("Cannot shrink structure below defined field at offset 0x" + Integer.toHexString(component.getOffset()));
				}
			}
		}
		int transaction = program.startTransaction("AETHER: resize structure");
		boolean commit = false;
		try {
			structure.setLength(length);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", structure.getPathName()));
	}

	private static Map<String, Object> createClass(Program program, Map<String, Object> arguments) {
		String className = required(arguments, "name");
		Map<String, Map<String, Object>> models = classModels(program);
		if (models.containsKey(className)) {
			throw new ProgramRegistry.BridgeException("already_exists", "Class already exists: " + className);
		}
		String structureName = optionalString(arguments, "structure");
		if (structureName == null) {
			structureName = className + "_data";
		}
		CategoryPath category = category(arguments);
		List<Map<String, Object>> fields = fields(arguments);
		int length = Math.max(integer(arguments, "size", integer(arguments, "length", 0)),
			requiredFieldEnd(program, fields));
		int transaction = program.startTransaction("AETHER: create class metadata");
		boolean commit = false;
		try {
			Structure structure = resolveOptionalStructure(program, structureName);
			if (structure == null) {
				StructureDataType requested = new StructureDataType(category, structureName, 0,
					program.getDataTypeManager());
				structure = (Structure) program.getDataTypeManager().addDataType(
					requested, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
			Map<String, Object> model = new LinkedHashMap<>(arguments);
			model.put("name", className);
			model.put("structure", structure.getPathName());
			model.remove("fields");
			if (model.get("rtti") == null && structure.getCategoryPath().getPath().contains("/ClassDataTypes/")) {
				model.put("rtti", Map.of("source", "ghidra_class_recovery"));
			}
			models.put(className, model);
			Map<String, Map<String, Object>> availableModels = allClassModels(program);
			availableModels.put(className, model);
			materializeBases(program, structure, listValue(model.get("bases")), availableModels);
			applyAddedFields(program, structure, fields(arguments));
			if (structure.getLength() < length) {
				structure.setLength(length);
			}
			ensureClassNamespace(program, className);
			saveClassModels(program, models);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", String.valueOf(models.get(className).get("structure"))));
	}

	private static Map<String, Object> updateClass(Program program, Map<String, Object> arguments) {
		Map<String, Map<String, Object>> models = classModels(program);
		Map<String, Map<String, Object>> available = allClassModels(program);
		String classKey = classModelKey(arguments, available);
		Map<String, Object> existing = available.get(classKey);
		if (existing == null) {
			throw new ProgramRegistry.BridgeException("not_found", "Class not found for the supplied identity");
		}
		String className = String.valueOf(existing.get("name"));
		int transaction = program.startTransaction("AETHER: update class metadata");
		boolean commit = false;
		try {
			Map<String, Object> updated = new LinkedHashMap<>(existing);
			for (String key : List.of("bases", "vtables", "methods", "rtti", "namespace", "confidence")) {
				if (arguments.containsKey(key)) {
					updated.put(key, arguments.get(key));
				}
			}
			updated.put("name", className);
			Structure structure = resolveOptionalStructure(program, String.valueOf(updated.get("structure")));
			if (structure == null) {
				throw new ProgramRegistry.BridgeException("not_found", "Backing structure not found for class: " + className);
			}
			Map<String, Map<String, Object>> availableModels = allClassModels(program);
			availableModels.put(classKey, updated);
			materializeBases(program, structure, listValue(updated.get("bases")), availableModels);
			models.put(classKey, updated);
			saveClassModels(program, models);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return getStruct(program, Map.of("path", String.valueOf(existing.get("structure"))));
	}

	private static Map<String, Object> deleteClass(Program program, Map<String, Object> arguments) {
		Map<String, Map<String, Object>> models = classModels(program);
		String classKey = classModelKey(arguments, allClassModels(program));
		Map<String, Object> removed = models.get(classKey);
		if (removed == null) {
			throw new ProgramRegistry.BridgeException("not_found", "Class metadata override not found for the supplied identity");
		}
		String className = String.valueOf(removed.get("name"));
		int transaction = program.startTransaction("AETHER: delete class metadata");
		boolean commit = false;
		try {
			models.remove(classKey);
			saveClassModels(program, models);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("deleted", className);
		result.put("structure", removed.get("structure"));
		result.put("metadata_only", true);
		return result;
	}

	private static Map<String, Object> structureSummary(Program program, Structure structure,
		Map<String, Map<String, Object>> models) {
		Map<String, Object> result = new LinkedHashMap<>();
		Map<String, Object> model = classModelFor(program, structure, models);
		result.put("name", structure.getName());
		result.put("path", structure.getPathName());
		result.put("category", structure.getCategoryPath().getPath());
		result.put("size", structure.getLength());
		result.put("field_count", structure.getNumDefinedComponents());
		result.put("kind", model == null ? "struct" : "class");
		if (model != null) {
			result.put("class_id", model.get("class_id"));
			result.put("qualified_name", model.getOrDefault("qualified_name", model.get("name")));
			result.put("class_name", model.get("name"));
			result.put("bases", model.getOrDefault("bases", List.of()));
			result.put("vtable_count", listValue(model.get("vtables")).size());
			result.put("rtti_available", model.get("rtti") != null);
			result.put("group_structures", groupStructures(program, structure, model));
		}
		else {
			result.put("class_name", null);
			result.put("vtable_count", 0);
			result.put("rtti_available", false);
		}
		return result;
	}

	private static Map<String, Object> classDetails(Program program, Structure structure,
		Map<String, Object> model,
		Map<String, Map<String, Object>> models) {
		Map<String, Object> result = new LinkedHashMap<>(model);
		result.put("group_structures", groupStructures(program, structure, model));
		List<Map<String, Object>> bases = new ArrayList<>();
		for (Object raw : listValue(model.get("bases"))) {
			if (raw instanceof Map<?, ?> rawMap) {
				bases.add(new LinkedHashMap<>(Json.object(rawMap)));
			}
			else {
				Map<String, Object> base = new LinkedHashMap<>();
				base.put("name", String.valueOf(raw));
				bases.add(base);
			}
		}
		result.put("bases", bases);
		result.put("non_virtual_functions", nonVirtualFunctions(program, model));
		List<String> chain = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		for (Map<String, Object> base : bases) {
			appendBaseChain(program, String.valueOf(base.get("name")), models, chain, seen);
		}
		result.put("inheritance_chain", chain);
		List<String> derived = new ArrayList<>();
		String name = String.valueOf(model.get("name"));
		for (Map<String, Object> candidate : models.values()) {
			for (Object raw : listValue(candidate.get("bases"))) {
				String baseName = raw instanceof Map<?, ?> map ? String.valueOf(map.get("name")) : String.valueOf(raw);
				if (name.equals(baseName)) {
					derived.add(String.valueOf(candidate.get("name")));
				}
			}
		}
		Iterator<Structure> analyzedStructures = program.getDataTypeManager().getAllStructures();
		while (analyzedStructures.hasNext()) {
			Structure candidate = analyzedStructures.next();
			if (!candidate.getCategoryPath().getPath().contains("/ClassDataTypes/")) {
				continue;
			}
			for (Map<String, Object> base : analyzedBases(candidate)) {
				if (name.equals(base.get("name"))) {
					derived.add(candidate.getName());
				}
			}
		}
		derived.sort(String::compareTo);
		result.put("derived_classes", derived);
		Namespace namespace = findClassNamespace(program, String.valueOf(model.get("name")));
		result.put("namespace", namespace == null ? model.get("namespace") : namespace.getName(true));
		return result;
	}

	private static List<Map<String, Object>> nonVirtualFunctions(Program program,
		Map<String, Object> model) {
		String className = String.valueOf(model.get("name"));
		Set<String> virtualAddresses = new HashSet<>();
		for (Map<String, Object> vtable : mapList(model.get("vtables"))) {
			for (Map<String, Object> slot : mapList(vtable.get("slots"))) {
				addAddressKey(virtualAddresses, slot.get("function"));
				addAddressKey(virtualAddresses, slot.get("canonical_function"));
			}
		}
		List<Map<String, Object>> result = new ArrayList<>();
		FunctionIterator functions = program.getFunctionManager().getFunctions(true);
		while (functions.hasNext()) {
			Function function = functions.next();
			Namespace parent = function.getParentNamespace();
			if (parent == null ||
				(!className.equals(parent.getName()) && !className.equals(parent.getName(true)))) {
				continue;
			}
			if (virtualAddresses.contains(Json.stringify(ProgramRegistry.addressMap(function.getEntryPoint()))) ||
				virtualAddresses.contains(Json.stringify(ProgramRegistry.addressMap(canonicalFunction(function))))) {
				continue;
			}
			Map<String, Object> method = new LinkedHashMap<>();
			method.put("name", function.getName());
			method.put("address", ProgramRegistry.addressMap(function.getEntryPoint()));
			method.put("signature", function.getPrototypeString(false, false));
			method.put("thunk", function.isThunk());
			result.add(method);
		}
		result.sort(Comparator.comparing(value -> String.valueOf(value.get("name"))));
		return result;
	}

	private static void addAddressKey(Set<String> addresses, Object rawFunction) {
		if (rawFunction instanceof Map<?, ?> map && map.get("address") != null) {
			addresses.add(Json.stringify(map.get("address")));
		}
	}

	private static Address canonicalFunction(Function function) {
		if (!function.isThunk()) {
			return function.getEntryPoint();
		}
		Function target = function.getThunkedFunction(true);
		return target == null ? function.getEntryPoint() : target.getEntryPoint();
	}

	private static List<Map<String, Object>> groupStructures(Program program, Structure dataStructure,
		Map<String, Object> model) {
		List<Map<String, Object>> result = new ArrayList<>();
		Set<String> paths = new HashSet<>();
		Map<String, Object> vtableAddresses = new LinkedHashMap<>();
		for (Object rawVtable : listValue(model.get("vtables"))) {
			if (!(rawVtable instanceof Map<?, ?> rawMap)) {
				continue;
			}
			Map<String, Object> vtable = Json.object(rawMap);
			Structure vtableStructure = findVtableStructure(program, String.valueOf(vtable.get("name")));
			if (vtableStructure != null) {
				vtableAddresses.put(vtableStructure.getPathName(), vtable.get("address"));
			}
		}
		List<Structure> siblings = new ArrayList<>();
		Iterator<Structure> structures = program.getDataTypeManager().getAllStructures();
		String className = dataStructure.getName();
		String classPrefix = className + "_";
		while (structures.hasNext()) {
			Structure candidate = structures.next();
			if (dataStructure.getCategoryPath().equals(candidate.getCategoryPath()) &&
				(candidate.getName().equals(className) || candidate.getName().startsWith(classPrefix))) {
				siblings.add(candidate);
			}
		}
		siblings.sort(Comparator.comparing(Structure::getName));
		for (Structure sibling : siblings) {
			Map<String, Object> member = new LinkedHashMap<>();
			member.put("role", structureRole(className, sibling.getName()));
			member.put("name", sibling.getName());
			member.put("path", sibling.getPathName());
			member.put("size", sibling.getLength());
			if (vtableAddresses.containsKey(sibling.getPathName())) {
				member.put("address", vtableAddresses.get(sibling.getPathName()));
			}
			paths.add(sibling.getPathName());
			result.add(member);
		}

		for (Object rawVtable : listValue(model.get("vtables"))) {
			if (!(rawVtable instanceof Map<?, ?> rawMap)) {
				continue;
			}
			Map<String, Object> vtable = Json.object(rawMap);
			Map<String, Object> member = new LinkedHashMap<>();
			member.put("role", "vtable");
			member.put("name", vtable.get("name"));
			member.put("address", vtable.get("address"));
			Structure vtableStructure = findVtableStructure(program, String.valueOf(vtable.get("name")));
			if (vtableStructure != null) {
				member.put("path", vtableStructure.getPathName());
				member.put("size", vtableStructure.getLength());
			}
			if (vtableStructure != null && paths.add(vtableStructure.getPathName())) {
				result.add(member);
			}
		}
		return result;
	}

	private static String structureRole(String className, String structureName) {
		if (className.equals(structureName)) {
			return "class";
		}
		if (structureName.equals(className + "_data")) {
			return "data class";
		}
		if (structureName.startsWith(className + "_vftable")) {
			return "vftable";
		}
		return "related struct";
	}

	private static boolean isClassGroupRoot(Program program, Structure structure,
		Map<String, Map<String, Object>> models) {
		Map<String, Object> directModel = modelFor(structure, models);
		if (directModel != null) {
			return structure.getPathName().equals(directModel.get("structure"));
		}
		String name = structure.getName();
		return !name.endsWith("_data") && !name.contains("_vftable");
	}

	private static Structure findVtableStructure(Program program, String name) {
		if (name == null || name.isBlank()) {
			return null;
		}
		SymbolIterator symbols = program.getSymbolTable().getSymbolIterator();
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (!name.equals(symbol.getName(true))) {
				continue;
			}
			Data data = program.getListing().getDataAt(symbol.getAddress());
			if (data != null && data.getDataType() instanceof Structure structure) {
				return structure;
			}
		}
		String generatedName = name.replace("::", "_");
		Iterator<Structure> structures = program.getDataTypeManager().getAllStructures();
		while (structures.hasNext()) {
			Structure structure = structures.next();
			if (generatedName.equals(structure.getName())) {
				return structure;
			}
		}
		return null;
	}

	private static void appendBaseChain(Program program, String name, Map<String, Map<String, Object>> models,
		List<String> chain, Set<String> seen) {
		if (!seen.add(name)) {
			return;
		}
		chain.add(name);
		List<?> bases;
		Map<String, Object> model = findModel(models, name);
		if (model != null) {
			bases = listValue(model.get("bases"));
		}
		else {
			Structure analyzed = findAnalyzedStructure(program, name);
			bases = analyzed == null ? List.of() : analyzedBases(analyzed);
		}
		for (Object raw : bases) {
			String base = raw instanceof Map<?, ?> map ? String.valueOf(map.get("name")) : String.valueOf(raw);
			appendBaseChain(program, base, models, chain, seen);
		}
	}

	private static Structure resolveStructure(Program program, Map<String, Object> arguments) {
		String value = optionalString(arguments, "path");
		if (value == null) {
			throw new ProgramRegistry.BridgeException("invalid_identity", "structure_path is required");
		}
		if (!value.startsWith("/")) {
			throw new ProgramRegistry.BridgeException("invalid_identity",
				"structure_path must be an absolute Ghidra datatype path");
		}
		Structure structure = resolveOptionalStructure(program, value);
		if (structure == null) {
			throw new ProgramRegistry.BridgeException("not_found", "Structure not found: " + value);
		}
		return structure;
	}

	private static String classModelKey(Map<String, Object> arguments,
		Map<String, Map<String, Object>> models) {
		String classId = optionalString(arguments, "class_id");
		String structure = optionalString(arguments, "structure");
		if (classId == null && structure == null) {
			throw new ProgramRegistry.BridgeException("invalid_identity",
				"class_id or structure_path is required");
		}
		if (classId != null) {
			for (Map.Entry<String, Map<String, Object>> entry : models.entrySet()) {
				if (classId.equals(entry.getKey()) || classId.equals(entry.getValue().get("class_id"))) {
					return entry.getKey();
				}
			}
			throw new ProgramRegistry.BridgeException("not_found", "Class identity not found: " + classId);
		}
		String match = null;
		for (Map.Entry<String, Map<String, Object>> entry : models.entrySet()) {
			if (!structure.equals(entry.getValue().get("structure"))) {
				continue;
			}
			if (match != null) {
				throw new ProgramRegistry.BridgeException("ambiguous_class",
					"Multiple class models use structure_path: " + structure);
			}
			match = entry.getKey();
		}
		if (match == null) {
			throw new ProgramRegistry.BridgeException("not_found", "Class structure not found: " + structure);
		}
		return match;
	}

	private static Structure resolveOptionalStructure(Program program, String value) {
		if (value == null || value.isBlank()) {
			return null;
		}
		DataTypeManager manager = program.getDataTypeManager();
		if (value.startsWith("/")) {
			int slash = value.lastIndexOf('/');
			if (slash >= 0) {
				DataType type = manager.getDataType(new DataTypePath(value.substring(0, slash), value.substring(slash + 1)));
				return type instanceof Structure structure ? structure : null;
			}
		}
		List<Structure> matches = new ArrayList<>();
		Iterator<Structure> iterator = manager.getAllStructures();
		while (iterator.hasNext()) {
			Structure structure = iterator.next();
			if (value.equals(structure.getName()) || value.equals(structure.getPathName())) {
				matches.add(structure);
			}
		}
		if (matches.size() > 1) {
			throw new ProgramRegistry.BridgeException("ambiguous_structure", "Structure name is ambiguous: " + value);
		}
		return matches.isEmpty() ? null : matches.get(0);
	}

	private static void applyAddedFields(Program program, Structure structure, List<Map<String, Object>> fields) {
		for (Map<String, Object> field : fields) {
			DataType type = parseDataType(program, required(field, "data_type"));
			int offset = integer(field, "offset", -1);
			int length = integer(field, "length", type.getLength());
			if (offset < 0 || length <= 0) {
				throw invalid("Fields require non-negative offsets and positive lengths");
			}
			structure.insertAtOffset(offset, type, length, optionalString(field, "name"), optionalString(field, "comment"));
		}
	}

	private static void materializeBases(Program program, Structure structure, List<?> bases,
		Map<String, Map<String, Object>> models) {
		for (Object raw : bases) {
			String baseName;
			Map<String, Object> base = raw instanceof Map<?, ?> map ? Json.object(map) : Map.of("name", String.valueOf(raw));
			baseName = optionalString(base, "name");
			if (baseName == null) {
				baseName = optionalString(base, "class_name");
			}
			String baseReference = optionalString(base, "structure");
			if (baseReference == null && baseName != null) {
				Map<String, Object> baseModel = findModel(models, baseName);
				baseReference = baseModel == null ? baseName : optionalString(baseModel, "structure");
			}
			Structure baseStructure = resolveOptionalStructure(program, baseReference);
			if (baseStructure == null || baseStructure == structure) {
				continue;
			}
			int offset = integer(base, "offset", 0);
			if (offset < 0 || baseStructure.getLength() <= 0) {
				throw invalid("Base structures require a non-negative offset and a positive size");
			}
			DataTypeComponent existing = definedComponentAt(structure, offset);
			if (existing != null) {
				if (existing.getLength() == baseStructure.getLength() &&
					existing.getDataType().getPathName().equals(baseStructure.getPathName())) {
					continue;
				}
				throw new ProgramRegistry.BridgeException("structure_conflict",
					"Base structure overlaps a field at offset 0x" + Integer.toHexString(offset));
			}
			int end = offset + baseStructure.getLength();
			if (end < offset) {
				throw invalid("Base structure range overflow");
			}
			if (end > structure.getLength()) {
				structure.growStructure(end - structure.getLength());
			}
			Map<String, Object> component = new LinkedHashMap<>();
			component.put("offset", offset);
			component.put("length", baseStructure.getLength());
			component.put("data_type", baseStructure.getPathName());
			component.put("name", baseName == null ? baseStructure.getName() : "base_" + baseName);
			component.put("comment", "C++ base class");
			validateNewFields(program, structure, List.of(component), Set.of());
			applyAddedFields(program, structure, List.of(component));
		}
	}

	private static void validateNewFields(Program program, Structure structure, List<Map<String, Object>> fields, Set<Integer> ignoredOffsets) {
		List<int[]> ranges = new ArrayList<>();
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			if (!ignoredOffsets.contains(component.getOffset())) {
				ranges.add(new int[] {component.getOffset(), component.getEndOffset()});
			}
		}
		for (Map<String, Object> field : fields) {
			int offset = integer(field, "offset", -1);
			int length = integer(field, "length", parseDataType(program, required(field, "data_type")).getLength());
			if (offset < 0 || length <= 0) {
				throw invalid("Fields require non-negative offsets and positive lengths");
			}
			int end = offset + length - 1;
			if (end < offset) {
				throw invalid("Field range overflow");
			}
			for (int[] range : ranges) {
				if (offset <= range[1] && end >= range[0]) {
					throw new ProgramRegistry.BridgeException("structure_conflict", "Field overlaps an existing field at offset 0x" + Integer.toHexString(range[0]));
				}
			}
			ranges.add(new int[] {offset, end});
		}
	}

	private static void validateReplacement(Structure structure, DataTypeComponent replaced, int offset, int length) {
		if (length <= 0) {
			throw invalid("Field length must be positive");
		}
		int end = offset + length - 1;
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			if (component == replaced) {
				continue;
			}
			if (offset <= component.getEndOffset() && end >= component.getOffset()) {
				throw new ProgramRegistry.BridgeException("structure_conflict", "Updated field overlaps field at offset 0x" + Integer.toHexString(component.getOffset()));
			}
		}
	}

	private static int requiredFieldEnd(Program program, List<Map<String, Object>> fields) {
		int end = 0;
		for (Map<String, Object> field : fields) {
			DataType type = parseDataType(program, required(field, "data_type"));
			int offset = integer(field, "offset", -1);
			int length = integer(field, "length", type.getLength());
			if (offset < 0 || length <= 0 || offset > Integer.MAX_VALUE - length) {
				throw invalid("Fields require valid non-negative offsets and positive lengths");
			}
			end = Math.max(end, offset + length);
		}
		return end;
	}

	private static DataType parseDataType(Program program, String specification) {
		try {
			if (specification != null && specification.startsWith("/")) {
				int slash = specification.lastIndexOf('/');
				if (slash > 0) {
					DataType referenced = program.getDataTypeManager().getDataType(
						new DataTypePath(specification.substring(0, slash), specification.substring(slash + 1)));
					if (referenced != null) {
						return referenced;
					}
				}
			}
			DataTypeParser parser = new DataTypeParser(program.getDataTypeManager(),
				program.getDataTypeManager(), null, DataTypeParser.AllowedDataTypes.ALL);
			return parser.parse(specification.trim());
		}
		catch (Exception e) {
			throw new ProgramRegistry.BridgeException("invalid_data_type",
				"Could not parse data type '" + specification + "': " + e.getMessage(), e);
		}
	}

	private static DataTypeComponent definedComponentAt(Structure structure, int offset) {
		for (DataTypeComponent component : structure.getDefinedComponents()) {
			if (component.getOffset() == offset) {
				return component;
			}
		}
		return null;
	}

	private static CategoryPath category(Map<String, Object> arguments) {
		String value = optionalString(arguments, "category");
		return new CategoryPath(value == null || value.isBlank() ? DEFAULT_CATEGORY : value);
	}

	private static List<Map<String, Object>> fields(Map<String, Object> arguments) {
		Object raw = arguments.get("fields");
		if (raw == null) {
			return new ArrayList<>();
		}
		if (!(raw instanceof List<?> list)) {
			throw invalid("fields must be an array");
		}
		List<Map<String, Object>> result = new ArrayList<>();
		for (Object value : list) {
			result.add(Json.object(value));
		}
		return result;
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Map<String, Object>> classModels(Program program) {
		Options options = program.getOptions(OPTIONS_NAME);
		String encoded = options.getString(CLASS_MODELS, "{}");
		try {
			Map<String, Object> parsed = Json.object(Json.parse(encoded));
			Map<String, Map<String, Object>> result = new LinkedHashMap<>();
			for (Map.Entry<String, Object> entry : parsed.entrySet()) {
				result.put(entry.getKey(), new LinkedHashMap<>(Json.object(entry.getValue())));
			}
			return result;
		}
		catch (RuntimeException e) {
			return new LinkedHashMap<>();
		}
	}

	private static Map<String, Map<String, Object>> allClassModels(Program program) {
		Map<String, Map<String, Object>> result = RttiAnalysisStore.load(program);
		result.putAll(classModels(program));
		return result;
	}

	private static void saveClassModels(Program program, Map<String, Map<String, Object>> models) {
		Map<String, Object> encoded = new LinkedHashMap<>();
		encoded.putAll(models);
		program.getOptions(OPTIONS_NAME).setString(CLASS_MODELS, Json.stringify(encoded));
	}

	private static Map<String, Object> modelFor(Structure structure, Map<String, Map<String, Object>> models) {
		for (Map<String, Object> model : models.values()) {
			if (structure.getPathName().equals(model.get("structure")) || structure.getName().equals(model.get("structure"))) {
				return model;
			}
		}
		return null;
	}

	private static Map<String, Object> findModel(Map<String, Map<String, Object>> models, String name) {
		Map<String, Object> direct = models.get(name);
		if (direct != null) {
			return direct;
		}
		for (Map<String, Object> model : models.values()) {
			if (name.equals(model.get("name")) || name.equals(model.get("qualified_name"))) {
				return model;
			}
		}
		return null;
	}

	private static Map<String, Object> classModelFor(Program program, Structure structure,
		Map<String, Map<String, Object>> models) {
		Map<String, Object> model = modelFor(structure, models);
		if (model != null) {
			return model;
		}
		if (!structure.getCategoryPath().getPath().contains("/ClassDataTypes/")) {
			return null;
		}
		Map<String, Object> analyzed = new LinkedHashMap<>();
		analyzed.put("name", structure.getName());
		analyzed.put("structure", structure.getPathName());
		analyzed.put("bases", analyzedBases(structure));
		analyzed.put("vtables", analyzedVtables(program, structure.getName()));
		analyzed.put("methods", List.of());
		analyzed.put("analysis_source", "ghidra_class_recovery");
		analyzed.put("rtti", true);
		return analyzed;
	}

	private static List<Map<String, Object>> analyzedVtables(Program program, String className) {
		List<Map<String, Object>> result = new ArrayList<>();
		var iterator = program.getSymbolTable().getSymbolIterator();
		while (iterator.hasNext()) {
			var symbol = iterator.next();
			String name = symbol.getName(true);
			if ((name.contains("vftable") || name.contains("vtable")) &&
				!isMetadataVtable(name) &&
				name.toLowerCase().contains(className.toLowerCase())) {
				Map<String, Object> vtable = new LinkedHashMap<>();
				vtable.put("name", name);
				vtable.put("address", ProgramRegistry.addressMap(symbol.getAddress()));
				result.add(vtable);
			}
		}
		return result;
	}

	private static List<Map<String, Object>> analyzedBases(Structure structure) {
		String description = structure.getDescription();
		if (description == null || !description.startsWith("class ")) {
			return List.of();
		}
		int separator = description.indexOf(" : ");
		if (separator < 0) {
			return List.of();
		}
		List<Map<String, Object>> bases = new ArrayList<>();
		for (String raw : description.substring(separator + 3).split(" : ")) {
			String value = raw.trim();
			boolean virtual = value.startsWith("virtual ");
			if (virtual) {
				value = value.substring("virtual ".length()).trim();
			}
			if (!value.isEmpty()) {
				Map<String, Object> base = new LinkedHashMap<>();
				base.put("name", value);
				base.put("virtual", virtual);
				base.put("source", "ghidra_class_recovery");
				bases.add(base);
			}
		}
		return bases;
	}

	private static Structure findAnalyzedStructure(Program program, String name) {
		String suffix = "/" + name.replace("::", "/");
		Iterator<Structure> iterator = program.getDataTypeManager().getAllStructures();
		while (iterator.hasNext()) {
			Structure structure = iterator.next();
			if (structure.getCategoryPath().getPath().contains("/ClassDataTypes/") &&
				name.substring(name.lastIndexOf("::") + 2).equals(structure.getName()) &&
				structure.getPathName().endsWith(suffix + "/" + structure.getName())) {
				return structure;
			}
		}
		return null;
	}

	private static Namespace findClassNamespace(Program program, String name) {
		Iterator<GhidraClass> iterator = program.getSymbolTable().getClassNamespaces();
		while (iterator.hasNext()) {
			GhidraClass namespace = iterator.next();
			if (name.equals(namespace.getName()) || name.equals(namespace.getName(true))) {
				return namespace;
			}
		}
		return null;
	}

	private static Namespace ensureClassNamespace(Program program, String name) {
		Namespace existing = findClassNamespace(program, name);
		if (existing != null) {
			return existing;
		}
		try {
			return program.getSymbolTable().createClass(program.getGlobalNamespace(), name, SourceType.USER_DEFINED);
		}
		catch (Exception e) {
			throw new ProgramRegistry.BridgeException("namespace_failed", "Could not create class namespace '" + name + "': " + e.getMessage(), e);
		}
	}

	private static List<?> listValue(Object value) {
		return value instanceof List<?> list ? list : List.of();
	}

	private static List<Map<String, Object>> mapList(Object value) {
		if (!(value instanceof List<?> list)) {
			return List.of();
		}
		List<Map<String, Object>> result = new ArrayList<>();
		for (Object item : list) {
			if (item instanceof Map<?, ?> map) {
				result.add(Json.object(map));
			}
		}
		return result;
	}

	private static boolean isMetadataVtable(String name) {
		String lower = name.toLowerCase();
		return lower.contains("meta_ptr") || lower.contains("metadata");
	}

	private static String required(Map<String, Object> arguments, String key) {
		String value = optionalString(arguments, key);
		if (value == null || value.isBlank()) {
			throw invalid(key + " is required");
		}
		return value.trim();
	}

	private static String optionalString(Map<String, Object> arguments, String key) {
		Object value = arguments.get(key);
		if (value == null) {
			return null;
		}
		if (!(value instanceof String string)) {
			throw invalid(key + " must be a string");
		}
		return string;
	}

	private static String optionalString(Map<String, Object> arguments, String key, String defaultValue) {
		String value = optionalString(arguments, key);
		return value == null ? defaultValue : value;
	}

	private static int integer(Map<String, Object> arguments, String key, int defaultValue) {
		Object value = arguments.get(key);
		return value == null ? defaultValue : asInteger(value, key);
	}

	private static int asInteger(Object value, String key) {
		if (value instanceof Number number) {
			return number.intValue();
		}
		if (value instanceof String string) {
			try {
				return Integer.decode(string);
			}
			catch (NumberFormatException ignored) {
			}
		}
		throw invalid(key + " must be an integer");
	}

	private static ProgramRegistry.BridgeException invalid(String message) {
		return new ProgramRegistry.BridgeException("invalid_argument", message);
	}
}
