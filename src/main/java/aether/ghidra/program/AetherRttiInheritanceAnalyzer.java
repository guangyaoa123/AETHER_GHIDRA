package aether.ghidra.program;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.VfTableModel;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import aether.ghidra.bridge.Json;

/** Extracts inheritance and virtual-dispatch relationships from RTTI already applied by Ghidra. */
public final class AetherRttiInheritanceAnalyzer extends AbstractAnalyzer {
	private static final String COMPLETE_LOCATOR = "RTTI_Complete_Object_Locator";
	private static final String CLASS_DATA_TYPES = "/ClassDataTypes/";

	public AetherRttiInheritanceAnalyzer() {
		super("AETHER RTTI Inheritance", "Builds a class inheritance and vtable/function graph from Ghidra RTTI data.",
			AnalyzerType.DATA_ANALYZER);
		setSupportsOneTimeAnalysis();
		setPriority(AnalysisPriority.REFERENCE_ANALYSIS.after());
		setDefaultEnablement(true);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program != null;
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
		throws CancelledException {
		Map<String, Map<String, Object>> classes = new LinkedHashMap<>();
		Map<String, Object> diagnostics = new LinkedHashMap<>();
		DataValidationOptions validation = new DataValidationOptions();
		validation.setValidateReferredToData(true);
		int locatorCount = 0;
		int classCount = 0;
		try {
			AnalyzerContext context = AnalyzerContext.of(program);
			for (Symbol locator : completeLocators(program, program.getMemory().getAllInitializedAddressSet())) {
				monitor.checkCancelled();
				locatorCount++;
				try {
					processLocator(context, program, locator, validation, classes, monitor);
				}
				catch (CancelledException e) {
					throw e;
				}
				catch (Exception e) {
					diagnostics.put(locator.getAddress().toString(), e.getMessage());
				}
			}
			processAnalyzedStructures(context, program, classes, monitor);
			linkVtableRelations(classes, monitor);
			classCount = classes.size();
		}
		finally {
			diagnostics.put("locator_count", locatorCount);
			diagnostics.put("class_count", classCount);
			diagnostics.put("analyzer", getName());
			RttiAnalysisStore.save(program, classes, diagnostics);
		}
		return true;
	}

	private static List<Symbol> completeLocators(Program program, AddressSetView set) {
		List<Symbol> result = new ArrayList<>();
		Set<Address> addresses = new HashSet<>();
		SymbolIterator symbols = program.getSymbolTable().getSymbols(set, SymbolType.LABEL, true);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (symbol.getName().contains(COMPLETE_LOCATOR) && addresses.add(symbol.getAddress())) {
				result.add(symbol);
			}
		}
		result.sort(Comparator.comparing(symbol -> symbol.getAddress().toString()));
		return result;
	}

	private static void processLocator(AnalyzerContext context, Program program, Symbol locator,
		DataValidationOptions validation, Map<String, Map<String, Object>> classes, TaskMonitor monitor)
		throws Exception {
		Rtti4Model rtti4 = new Rtti4Model(program, locator.getAddress(), validation);
		TypeDescriptorModel typeDescriptor = rtti4.getRtti0Model();
		String classId = classId(typeDescriptor);
		String className = className(typeDescriptor);
		if (className == null || className.isBlank()) {
			return;
		}
		String classPath = classPath(context, className);
		Map<String, Object> model = classes.computeIfAbsent(classId,
			ignored -> newClassModel(classId, className, namespace(typeDescriptor), classPath));
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> rtti = (List<Map<String, Object>>) model.get("rtti");
		Map<String, Object> evidence = new LinkedHashMap<>();
		evidence.put("abi", "msvc");
		evidence.put("complete_object_locator", ProgramRegistry.addressMap(locator.getAddress()));
		rtti.add(evidence);

		Rtti3Model rtti3 = rtti4.getRtti3Model();
		if (rtti3 != null) {
			addDirectBases(context, program, model, rtti3, validation, monitor);
		}
		for (VtableReference vtable : vtablesFor(program, locator.getAddress())) {
			modelVtable(program, model, vtable, typeDescriptor, validation, monitor);
		}
	}

	private static void addDirectBases(AnalyzerContext context, Program program, Map<String, Object> model,
		Rtti3Model rtti3, DataValidationOptions validation, TaskMonitor monitor) throws Exception {
		Rtti2Model rtti2 = rtti3.getRtti2Model();
		if (rtti2 == null) {
			return;
		}
		int count = rtti3.getRtti1Count();
		// The first entry describes the complete (most-derived) class itself.
		int index = 1;
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> bases = (List<Map<String, Object>>) model.get("bases");
		while (index < count) {
			monitor.checkCancelled();
			Rtti1Model baseModel = rtti2.getRtti1Model(index);
			TypeDescriptorModel baseType = baseModel.getRtti0Model();
			String baseId = classId(baseType);
			String baseName = className(baseType);
			if (baseName != null && !baseId.equals(model.get("class_id")) &&
				bases.stream().noneMatch(existing -> baseId.equals(existing.get("class_id")))) {
				Map<String, Object> base = new LinkedHashMap<>();
				base.put("class_id", baseId);
				base.put("name", baseName);
				base.put("qualified_name", baseName);
				base.put("namespace", namespace(baseType));
				String basePath = classPath(context, baseName);
				base.put("structure_path", basePath);
				base.put("class_path", basePath);
				base.put("offset", baseModel.getMDisp());
				base.put("pdisp", baseModel.getPDisp());
				base.put("vdisp", baseModel.getVDisp());
				base.put("virtual", baseModel.getPDisp() != -1);
				base.put("source", "msvc_rtti");
				bases.add(base);
			}
			// numBases counts extended entries, while the array is preorder.
			index += Math.max(1, baseModel.getNumBases() + 1);
		}
	}

	private static void modelVtable(Program program, Map<String, Object> model, VtableReference reference,
		TypeDescriptorModel typeDescriptor, DataValidationOptions validation, TaskMonitor monitor)
		throws Exception {
		Map<String, Object> vtable = new LinkedHashMap<>();
		vtable.put("address", ProgramRegistry.addressMap(reference.vtableAddress()));
		vtable.put("meta_pointer", ProgramRegistry.addressMap(reference.metaPointerAddress()));
		vtable.put("slots", vtableSlots(program, reference.vtableAddress(), validation, monitor));
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> vtables = (List<Map<String, Object>>) model.get("vtables");
		String address = Json.stringify(ProgramRegistry.addressMap(reference.vtableAddress()));
		for (Map<String, Object> existing : vtables) {
			if (address.equals(Json.stringify(existing.get("address")))) {
				return;
			}
		}
		vtables.add(vtable);
	}

	private static void processAnalyzedStructures(AnalyzerContext context, Program program,
		Map<String, Map<String, Object>> classes, TaskMonitor monitor) throws CancelledException {
		Iterator<Structure> structures = program.getDataTypeManager().getAllStructures();
		while (structures.hasNext()) {
			monitor.checkCancelled();
			Structure structure = structures.next();
			if (!structure.getCategoryPath().getPath().contains("/ClassDataTypes/")) {
				continue;
			}
			if (!isRecoveredClassStructure(context, structure)) {
				continue;
			}
			String className = structure.getName();
			String classId = null;
			for (Map.Entry<String, Map<String, Object>> entry : classes.entrySet()) {
				if (structure.getPathName().equals(entry.getValue().get("structure"))) {
					classId = entry.getKey();
					break;
				}
			}
			if (classId == null) {
				classId = "structure:" + structure.getPathName();
			}
			String modelId = classId;
			Map<String, Object> model = classes.computeIfAbsent(modelId,
				ignored -> newClassModel(modelId, className, null, structure.getPathName()));
			model.put("analysis_source", "ghidra_class_recovery");
			@SuppressWarnings("unchecked")
			List<Map<String, Object>> rtti = (List<Map<String, Object>>) model.get("rtti");
			if (rtti.isEmpty()) {
				rtti.add(Map.of("abi", "ghidra_class_recovery", "structure", structure.getPathName()));
			}
			@SuppressWarnings("unchecked")
			List<Map<String, Object>> bases = (List<Map<String, Object>>) model.get("bases");
			for (Map<String, Object> base : bases) {
				enrichBaseIdentity(context, base, classes);
			}
			if (bases.isEmpty()) {
				for (Map<String, Object> base : analyzedBases(context, program, structure)) {
					enrichBaseIdentity(context, base, classes);
					if (bases.stream().noneMatch(existing -> existing.get("name").equals(base.get("name")))) {
						bases.add(base);
					}
				}
			}
			for (Symbol symbol : symbolsForClass(context, className)) {
				modelGenericVtable(program, model, symbol, monitor);
			}
		}
	}

	private static List<Symbol> symbolsForClass(AnalyzerContext context, String className) {
		List<Symbol> result = context.vtablesByNamespace.get(className);
		return result == null ? List.of() : result;
	}

	private static void modelGenericVtable(Program program, Map<String, Object> model,
		Symbol symbol, TaskMonitor monitor) throws CancelledException {
		@SuppressWarnings("unchecked")
		List<Map<String, Object>> vtables = (List<Map<String, Object>>) model.get("vtables");
		Map<String, Object> vtable = new LinkedHashMap<>();
		vtable.put("name", symbol.getName(true));
		vtable.put("address", ProgramRegistry.addressMap(symbol.getAddress()));
		vtable.put("slots", genericVtableSlots(program, symbol.getAddress(), monitor));
		String address = Json.stringify(vtable.get("address"));
		if (vtables.stream().noneMatch(existing -> address.equals(Json.stringify(existing.get("address"))))) {
			vtables.add(vtable);
		}
	}

	private static List<Map<String, Object>> genericVtableSlots(Program program, Address address,
		TaskMonitor monitor) throws CancelledException {
		List<Map<String, Object>> result = new ArrayList<>();
		Data data = program.getListing().getDataAt(address);
		if (data == null) {
			return result;
		}
		for (int index = 0; index < data.getNumComponents(); index++) {
			monitor.checkCancelled();
			Data component = data.getComponent(index);
			if (component == null || component.getValueReferences().length == 0) {
				continue;
			}
			Address functionAddress = component.getValueReferences()[0].getToAddress();
			if (functionAddress == null) {
				continue;
			}
			Map<String, Object> slot = new LinkedHashMap<>();
			slot.put("index", index);
			slot.put("function", functionMap(program, functionAddress));
			slot.put("canonical_function", functionMap(program, canonicalFunction(program, functionAddress)));
			result.add(slot);
		}
		return result;
	}

	private static List<Map<String, Object>> analyzedBases(AnalyzerContext context, Program program,
		Structure structure) {
		String description = structure.getDescription();
		if (description == null || !description.startsWith("class ")) {
			return List.of();
		}
		int separator = description.indexOf(" : ");
		if (separator < 0) {
			return List.of();
		}
		List<Map<String, Object>> result = new ArrayList<>();
		for (String raw : description.substring(separator + 3).split(" : ")) {
			String name = raw.trim();
			boolean virtual = name.startsWith("virtual ");
			if (virtual) {
				name = name.substring("virtual ".length()).trim();
			}
			if (!name.isEmpty()) {
				Map<String, Object> base = new LinkedHashMap<>();
				base.put("name", name);
				String path = classPath(context, name);
				base.put("class_id", path == null ? null : "structure:" + path);
				base.put("structure_path", path);
				base.put("class_path", path);
				base.put("virtual", virtual);
				base.put("source", "ghidra_class_recovery");
				result.add(base);
			}
		}
		return result;
	}

	private static void enrichBaseIdentity(AnalyzerContext context, Map<String, Object> base,
		Map<String, Map<String, Object>> classes) {
		String name = base.get("name") == null ? null : String.valueOf(base.get("name"));
		if (name == null || name.isBlank()) {
			return;
		}
		String path = base.get("structure_path") == null ? null : String.valueOf(base.get("structure_path"));
		if (path == null || path.isBlank() || "null".equals(path)) {
			path = classPath(context, name);
		}
		for (Map<String, Object> candidate : classes.values()) {
			if (!name.equals(candidate.get("name"))) {
				continue;
			}
			if (base.get("class_id") == null) {
				base.put("class_id", candidate.get("class_id"));
			}
			if (path == null || path.isBlank() || "null".equals(path)) {
				Object candidatePath = candidate.get("structure");
				if (candidatePath != null && !String.valueOf(candidatePath).isBlank()) {
					path = String.valueOf(candidatePath);
				}
			}
			break;
		}
		if (path != null) {
			base.put("structure_path", path);
			base.put("class_path", path);
			if (base.get("class_id") == null) {
				base.put("class_id", "structure:" + path);
			}
		}
	}

	private static boolean isRecoveredClassStructure(AnalyzerContext context, Structure structure) {
		String description = structure.getDescription();
		if (description != null && description.startsWith("class ")) {
			return true;
		}
		return context.classNamespaceNames.contains(structure.getName());
	}

	private static List<Map<String, Object>> vtableSlots(Program program, Address vtableAddress,
		DataValidationOptions validation, TaskMonitor monitor) throws Exception {
		List<Map<String, Object>> slots = new ArrayList<>();
		try {
			VfTableModel table = new VfTableModel(program, vtableAddress, validation);
			for (int index = 0; index < table.getElementCount(); index++) {
				monitor.checkCancelled();
				Address functionAddress = table.getVirtualFunctionPointer(index);
				if (functionAddress == null) {
					continue;
				}
				Map<String, Object> slot = new LinkedHashMap<>();
				slot.put("index", index);
				slot.put("function", functionMap(program, functionAddress));
				slot.put("canonical_function", functionMap(program, canonicalFunction(program, functionAddress)));
				slots.add(slot);
			}
		}
		catch (CancelledException e) {
			throw e;
		}
		catch (Exception ignored) {
			// The RTTI graph remains useful when a vtable was named but not fully applied.
		}
		return slots;
	}

	private static Address canonicalFunction(Program program, Address address) {
		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function == null || !function.isThunk()) {
			return address;
		}
		Function target = function.getThunkedFunction(true);
		return target == null ? address : target.getEntryPoint();
	}

	private static Map<String, Object> functionMap(Program program, Address address) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("address", ProgramRegistry.addressMap(address));
		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function != null) {
			result.put("name", function.getName());
			Namespace parent = function.getParentNamespace();
			String namespace = parent == null || parent.isGlobal() ? null : parent.getName(true);
			result.put("namespace", namespace);
			result.put("qualified_name", namespace == null || namespace.isBlank()
				? function.getName() : namespace + "::" + function.getName());
			result.put("thunk", function.isThunk());
		}
		else {
			Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
			result.put("name", symbol == null ? address.toString() : symbol.getName(true));
			result.put("thunk", false);
		}
		return result;
	}

	private static List<VtableReference> vtablesFor(Program program, Address locatorAddress) {
		List<VtableReference> result = new ArrayList<>();
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(locatorAddress);
		Set<Address> seen = new HashSet<>();
		int pointerSize = program.getDefaultPointerSize();
		while (references.hasNext()) {
			Reference reference = references.next();
			Address metaPointer = reference.getFromAddress();
			if (metaPointer == null) {
				continue;
			}
			try {
				Address vtable = metaPointer.add(pointerSize);
				if (seen.add(vtable)) {
					result.add(new VtableReference(metaPointer, vtable));
				}
			}
			catch (RuntimeException ignored) {
			}
		}
		return result;
	}

	private static Map<String, Object> newClassModel(String classId, String name, String namespace, String path) {
		Map<String, Object> model = new LinkedHashMap<>();
		model.put("class_id", classId);
		model.put("name", name);
		model.put("qualified_name", name);
		if (namespace != null && !namespace.isBlank()) {
			model.put("namespace", namespace);
		}
		model.put("structure", path);
		model.put("analysis_source", "aether_rtti_analyzer");
		model.put("bases", new ArrayList<Map<String, Object>>());
		model.put("vtables", new ArrayList<Map<String, Object>>());
		model.put("methods", new ArrayList<Map<String, Object>>());
		model.put("rtti", new ArrayList<Map<String, Object>>());
		return model;
	}

	private static String className(TypeDescriptorModel descriptor) {
		try {
			String qualified = descriptor.getDescriptorTypeNamespace();
			if (qualified != null && !qualified.isBlank()) {
				return qualified;
			}
			String name = descriptor.getDescriptorName();
			return name != null && !name.isBlank() ? name : descriptor.getTypeName();
		}
		catch (Exception ignored) {
			return null;
		}
	}

	private static String classId(TypeDescriptorModel descriptor) {
		try {
			return "rtti0:" + descriptor.getAddress();
		}
		catch (Exception ignored) {
			return "name:" + className(descriptor);
		}
	}

	private static String namespace(TypeDescriptorModel descriptor) {
		String name = className(descriptor);
		if (name == null) {
			return null;
		}
		int separator = name.lastIndexOf("::");
		return separator < 0 ? null : name.substring(0, separator);
	}

	/**
	 * Resolves the ClassDataTypes structure path for a possibly qualified class
	 * name. Preserves the previous first-match-in-DTM-order semantics across the
	 * exact-path and short-name predicates by comparing DTM order indexes.
	 */
	private static String classPath(AnalyzerContext context, String name) {
		String shortName = name.substring(name.lastIndexOf("::") + 2);
		String expected = "/ClassDataTypes/" + name.replace("::", "/") + "/" + shortName;
		Structure exact = context.structureByPath.get(expected);
		Structure byName = context.classStructureByName.get(shortName);
		if (exact == null) {
			return byName == null ? null : byName.getPathName();
		}
		if (byName == null) {
			return exact.getPathName();
		}
		Integer exactOrder = context.structureOrder.get(exact);
		Integer nameOrder = context.structureOrder.get(byName);
		if (exactOrder != null && nameOrder != null && nameOrder < exactOrder) {
			return byName.getPathName();
		}
		return exact.getPathName();
	}

	/**
	 * One-pass indexes for a single analyzer run. The previous code re-scanned
	 * the symbol table, the data type manager, and the class namespaces per
	 * class or per base, which made graph recompute quadratic on large programs.
	 */
	private static final class AnalyzerContext {
		final Map<String, List<Symbol>> vtablesByNamespace = new HashMap<>();
		final Map<String, Structure> structureByPath = new HashMap<>();
		final Map<String, Structure> classStructureByName = new HashMap<>();
		final Map<Structure, Integer> structureOrder = new IdentityHashMap<>();
		final Set<String> classNamespaceNames = new HashSet<>();

		static AnalyzerContext of(Program program) {
			AnalyzerContext context = new AnalyzerContext();
			SymbolIterator symbols = program.getSymbolTable().getSymbolIterator();
			while (symbols.hasNext()) {
				Symbol symbol = symbols.next();
				Namespace parent = symbol.getParentNamespace();
				if (parent == null) {
					continue;
				}
				String name = symbol.getName(true).toLowerCase();
				if ((name.contains("vtable") || name.contains("vftable")) && !isMetadataVtable(name)) {
					context.vtablesByNamespace.computeIfAbsent(parent.getName(),
						ignored -> new ArrayList<>()).add(symbol);
				}
			}
			Iterator<GhidraClass> namespaces = program.getSymbolTable().getClassNamespaces();
			while (namespaces.hasNext()) {
				context.classNamespaceNames.add(namespaces.next().getName());
			}
			int order = 0;
			Iterator<Structure> structures = program.getDataTypeManager().getAllStructures();
			while (structures.hasNext()) {
				Structure structure = structures.next();
				context.structureByPath.put(structure.getPathName(), structure);
				if (structure.getCategoryPath().getPath().contains(CLASS_DATA_TYPES)) {
					context.classStructureByName.putIfAbsent(structure.getName(), structure);
				}
				context.structureOrder.put(structure, order++);
			}
			return context;
		}
	}

	private record VtableReference(Address metaPointerAddress, Address vtableAddress) {
	}

	private static void linkVtableRelations(Map<String, Map<String, Object>> classes,
		TaskMonitor monitor) throws CancelledException {
		for (Map<String, Object> child : classes.values()) {
			String childId = modelId(child);
			for (String parentId : ancestors(childId, classes, new HashSet<>())) {
				Map<String, Object> parent = classes.get(parentId);
				if (parent == null) {
					continue;
				}
				String parentName = String.valueOf(parent.get("name"));
				for (Map<String, Object> childVtable : mapList(child.get("vtables"))) {
					if (!vtableRepresentsParent(child, childVtable, parentId, parentName)) {
						continue;
					}
					for (Map<String, Object> parentVtable : mapList(parent.get("vtables"))) {
						linkSlots(childVtable, parentVtable, parentId, parentName, monitor);
					}
				}
			}
		}
	}

	private static boolean vtableRepresentsParent(Map<String, Object> child,
		Map<String, Object> childVtable, String parentId, String parentName) {
		Object rawName = childVtable.get("name");
		if (rawName instanceof String name) {
			String marker = "for_" + parentName.toLowerCase();
			if (name.toLowerCase().contains(marker)) {
				return true;
			}
			if (name.toLowerCase().contains("for_")) {
				return false;
			}
		}
		List<Map<String, Object>> bases = mapList(child.get("bases"));
		return !bases.isEmpty() && (parentId.equals(baseId(bases.get(0))) ||
			parentName.equals(String.valueOf(bases.get(0).get("name"))));
	}

	private static List<String> ancestors(String name, Map<String, Map<String, Object>> classes,
		Set<String> visited) {
		String modelKey = resolveModelKey(name, classes);
		if (!visited.add(modelKey)) {
			return List.of();
		}
		List<String> result = new ArrayList<>();
		Map<String, Object> model = classes.get(modelKey);
		if (model == null) {
			return result;
		}
		for (Map<String, Object> base : mapList(model.get("bases"))) {
			String baseId = resolveModelKey(baseId(base), classes);
			result.add(baseId);
			result.addAll(ancestors(baseId, classes, visited));
		}
		return result;
	}

	private static void linkSlots(Map<String, Object> childVtable, Map<String, Object> parentVtable,
		String parentId, String parentName, TaskMonitor monitor) throws CancelledException {
		Map<Integer, Map<String, Object>> parentSlots = new HashMap<>();
		for (Map<String, Object> parentSlot : mapList(parentVtable.get("slots"))) {
			Object index = parentSlot.get("index");
			if (index instanceof Number number) {
				parentSlots.put(number.intValue(), parentSlot);
			}
		}
		for (Map<String, Object> childSlot : mapList(childVtable.get("slots"))) {
			monitor.checkCancelled();
			Object index = childSlot.get("index");
			if (!(index instanceof Number number)) {
				continue;
			}
			Map<String, Object> parentSlot = parentSlots.get(number.intValue());
			if (parentSlot == null) {
				continue;
			}
			Map<String, Object> relation = new LinkedHashMap<>();
			relation.put("parent_class_id", parentId);
			relation.put("parent_class", parentName);
			relation.put("parent_vtable", parentVtable.get("address"));
			relation.put("parent_slot", parentSlot.get("index"));
			relation.put("function", parentSlot.get("function"));
			String childAddress = addressString(childSlot.get("canonical_function"));
			String parentAddress = addressString(parentSlot.get("canonical_function"));
			String relationKind = childAddress.equals(parentAddress) ? "inherited" : "override";
			relation.put("relation", relationKind);
			@SuppressWarnings("unchecked")
			List<Map<String, Object>> relations = (List<Map<String, Object>>) childSlot.computeIfAbsent(
				"parent_relations", ignored -> new ArrayList<Map<String, Object>>());
			relations.add(relation);
			if (!childSlot.containsKey("relation") || "override".equals(relationKind)) {
				childSlot.put("relation", relationKind);
			}
		}
	}

	private static String addressString(Object function) {
		if (!(function instanceof Map<?, ?> map)) {
			return "";
		}
		return Json.stringify(map.get("address"));
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

	private static String modelId(Map<String, Object> model) {
		Object value = model.get("class_id");
		return value == null ? String.valueOf(model.get("name")) : String.valueOf(value);
	}

	private static String resolveModelKey(String identity, Map<String, Map<String, Object>> classes) {
		if (classes.containsKey(identity)) {
			return identity;
		}
		for (Map.Entry<String, Map<String, Object>> entry : classes.entrySet()) {
			Map<String, Object> model = entry.getValue();
			if (identity.equals(model.get("name")) || identity.equals(model.get("qualified_name")) ||
				identity.equals(model.get("class_id"))) {
				return entry.getKey();
			}
		}
		return identity;
	}

	private static String baseId(Map<String, Object> base) {
		Object value = base.get("class_id");
		return value == null ? String.valueOf(base.get("name")) : String.valueOf(value);
	}

	private static boolean isMetadataVtable(String name) {
		String lower = name.toLowerCase();
		return lower.contains("meta_ptr") || lower.contains("metadata");
	}
}
