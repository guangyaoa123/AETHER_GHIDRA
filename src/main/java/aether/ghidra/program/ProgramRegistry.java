package aether.ghidra.program;

import java.io.File;
import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.options.Options;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainObject;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypePath;
import ghidra.program.model.data.Structure;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.data.DataTypeParser;

import aether.ghidra.bridge.Json;
import aether.ghidra.observability.DebugLog;

/** Owns the session-scoped identities for all Programs open in one Ghidra Tool. */
public final class ProgramRegistry {
	private final PluginTool tool;
	private final ProgramManager programManager;
	private final Project project;
	private final ProjectData projectData;
	private final Object lock = new Object();
	private final Object importLock = new Object();
	private final Map<String, ProgramContext> byId = new LinkedHashMap<>();
	private final IdentityHashMap<Program, String> byProgram = new IdentityHashMap<>();
	private final Set<Program> ownedPrograms = java.util.Collections.newSetFromMap(new IdentityHashMap<>());
	private final ClassGraphRefresher classGraphRefresher = new ClassGraphRefresher();

	/** Capabilities whose writes change data stored inside the class graph. */
	private static final Set<String> GRAPH_AFFECTING_CAPABILITIES = Set.of(
		"rename_function", "update_function_definition", "apply_annotation_batch");

	public ProgramRegistry(PluginTool tool) {
		if (tool == null) {
			throw new IllegalStateException("PluginTool is required");
		}
		this.tool = tool;
		this.project = tool.getProject();
		this.projectData = project == null ? null : project.getProjectData();
		this.programManager = tool.getService(ProgramManager.class);
		if (programManager == null) {
			throw new IllegalStateException("Ghidra ProgramManager service is unavailable");
		}
	}

	/** Creates a registry for one Program, used by headless Ghidra scripts. */
	public ProgramRegistry(Program program) {
		this(List.of(program));
	}

	/** Creates a registry for all Programs opened from one headless project. */
	public ProgramRegistry(List<Program> programs) {
		this.tool = null;
		this.programManager = null;
		this.project = null;
		this.projectData = null;
		if (programs != null) {
			for (Program program : programs) {
				register(program);
			}
			if (!programs.isEmpty()) {
				setActive(programs.get(0));
			}
		}
	}

	/** Creates a registry backed by one live headless Ghidra Project. */
	public ProgramRegistry(Project project, Program initialProgram) {
		if (project == null) {
			throw new IllegalStateException("Project is required");
		}
		this.tool = null;
		this.programManager = null;
		this.project = project;
		this.projectData = project.getProjectData();
		if (initialProgram != null) {
			register(initialProgram);
			setActive(initialProgram);
		}
	}

	public void refreshOpenPrograms() {
		if (programManager == null) {
			return;
		}
		for (Program program : programManager.getAllOpenPrograms()) {
			register(program);
		}
		setActive(programManager.getCurrentProgram());
	}

	public void register(Program program) {
		if (program == null) {
			return;
		}
		synchronized (lock) {
			if (byProgram.containsKey(program)) {
				return;
			}
			String id = programId(program);
			ProgramContext existing = byId.get(id);
			if (existing != null && existing.program() != program) {
				throw new BridgeException("program_conflict", "Another Program is already open at " + id);
			}
			DebugLog.debug(this, "registered program_id=" + id);
			byProgram.put(program, id);
			byId.put(id, new ProgramContext(id, program));
		}
	}

	public void unregister(Program program) {
		if (program == null) {
			return;
		}
		synchronized (lock) {
			String id = byProgram.remove(program);
			if (id != null) {
				DebugLog.debug(this, "unregistered program_id=" + id);
				byId.remove(id);
			}
		}
	}

	public String idFor(Program program) {
		synchronized (lock) {
			return byProgram.get(program);
		}
	}

	public Program programFor(String programId) {
		synchronized (lock) {
			ProgramContext context = byId.get(programId);
			return context == null ? null : context.program();
		}
	}

	public void setActive(Program program) {
		synchronized (lock) {
			for (ProgramContext context : byId.values()) {
				context.setActive(context.program() == program);
			}
		}
	}

	public List<Map<String, Object>> listPrograms() {
		synchronized (lock) {
			if (projectData != null) {
				projectData.refresh(true);
				List<Map<String, Object>> result = new ArrayList<>();
				for (DomainFile file : projectData) {
					if (!isProgram(file)) {
						continue;
					}
					String id = normalizeProgramId(file.getPathname());
					ProgramContext open = byId.get(id);
					if (open != null) {
						result.add(open.metadata());
					}
					else {
						Map<String, Object> item = new LinkedHashMap<>();
						item.put("program_id", id);
						item.put("project_path", id);
						item.put("name", file.getName());
						item.put("state", "closed");
						item.put("dirty", false);
						item.put("active", false);
						result.add(item);
					}
				}
				return result;
			}
			List<Map<String, Object>> result = new ArrayList<>();
			for (ProgramContext context : byId.values()) {
				result.add(context.metadata());
			}
			return result;
		}
	}

	public Map<String, Object> projectMetadata() {
		if (project == null) {
			return Map.of("state", "unavailable");
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("gpr_path", project.getProjectLocator().getMarkerFile().getAbsolutePath());
		result.put("name", project.getName());
		result.put("state", project.isClosed() ? "closed" : "open");
		result.put("program_count", listPrograms().size());
		synchronized (lock) {
			result.put("open_program_count", byId.size());
		}
		return result;
	}

	public Map<String, Object> openProgram(String programId) {
		String id = normalizeProgramId(programId);
		synchronized (lock) {
			ProgramContext existing = byId.get(id);
			if (existing != null) {
				return existing.metadata();
			}
		}
		if (projectData == null) {
			throw new BridgeException("project_unavailable", "The current backend cannot open stored Programs");
		}
		DomainFile file = projectData.getFile(id);
		if (file == null || !isProgram(file)) {
			throw new BridgeException("program_not_found", "Program does not exist in the project: " + id);
		}
		try {
			DomainObject object = file.getDomainObject(this, true, true, TaskMonitor.DUMMY);
			if (!(object instanceof Program program)) {
				object.release(this);
				throw new BridgeException("program_not_found", "Project item is not a Program: " + id);
			}
			if (programManager != null) {
				programManager.openProgram(program, ProgramManager.OPEN_VISIBLE);
				program.release(this);
			}
			else {
				ownedPrograms.add(program);
			}
			register(program);
			return metadataFor(id);
		}
		catch (BridgeException error) {
			throw error;
		}
		catch (Exception error) {
			throw new BridgeException("program_open_failed", "Could not open " + id + ": " + error.getMessage(), error);
		}
	}

	public Map<String, Object> closeProgram(String programId) {
		String id = normalizeProgramId(programId);
		ProgramContext context;
		synchronized (lock) {
			context = byId.get(id);
		}
		if (context == null) {
			throw new BridgeException("program_not_open", "Program is not open: " + id);
		}
		synchronized (context) {
			Program program = context.program();
			Map<String, Object> saved = saveProgram(program);
			if (programManager != null) {
				if (!programManager.closeProgram(program, false)) {
					throw new BridgeException("program_close_failed", "Ghidra refused to close " + id);
				}
			}
			else if (ownedPrograms.remove(program)) {
				program.release(this);
			}
			unregister(program);
			return Map.of("program_id", id, "closed", true, "saved", saved.get("saved"));
		}
	}

	private static boolean isProgram(DomainFile file) {
		Class<? extends DomainObject> type = file.getDomainObjectClass();
		return type != null && Program.class.isAssignableFrom(type);
	}

	private static String programId(Program program) {
		DomainFile file = program.getDomainFile();
		return normalizeProgramId(file == null ? program.getName() : file.getPathname());
	}

	private static String normalizeProgramId(String value) {
		if (value == null || value.isBlank()) {
			throw new BridgeException("invalid_identity", "program_id is required");
		}
		String normalized = value.trim().replace('\\', '/');
		return normalized.startsWith("/") ? normalized : "/" + normalized;
	}

	/** Imports one or more Programs into the interactive tool project. */
	public Map<String, Object> importProgram(File source) {
		if (project == null) {
			throw new BridgeException("project_unavailable", "Imports require an open Ghidra Project");
		}
		if (source == null || !source.isFile()) {
			throw new BridgeException("invalid_argument",
				"Import source must exist and be a regular file: " + source);
		}
		if (project == null || project.isClosed()) {
			throw new BridgeException("project_unavailable", "Imports require an open Ghidra project");
		}

		synchronized (importLock) {
			try (LoadResults<Program> loadResults = ProgramLoader.builder()
				.source(source)
				.project(project)
				.load()) {
				List<Program> loadedPrograms = new ArrayList<>();
				try {
					loadResults.save(TaskMonitor.DUMMY);
					Loaded<Program> primaryLoaded = loadResults.getPrimary();
					Program primary = primaryLoaded.getDomainObject(this);
					loadedPrograms.add(primary);
					for (Loaded<Program> loaded : loadResults.getNonPrimary()) {
						loadedPrograms.add(loaded.getDomainObject(this));
					}

					for (int index = 0; index < loadedPrograms.size(); index++) {
						Program program = loadedPrograms.get(index);
						if (programManager != null) {
							programManager.openProgram(program,
								index == 0 ? ProgramManager.OPEN_CURRENT : ProgramManager.OPEN_VISIBLE);
						}
						else {
							ownedPrograms.add(program);
						}
						register(program);
						startAnalysis(program);
					}

					List<Map<String, Object>> programs = new ArrayList<>();
					List<String> programIds = new ArrayList<>();
					for (Program program : loadedPrograms) {
						String programId = idFor(program);
						programIds.add(programId);
						programs.add(metadataFor(programId));
					}
					Map<String, Object> result = new LinkedHashMap<>();
					result.put("primary_program_id", programIds.get(0));
					result.put("program_ids", programIds);
					result.put("programs", programs);
					return result;
				}
				finally {
					// ProgramManager owns opened Programs; release only this temporary consumer.
					for (Program program : loadedPrograms) {
						if (programManager != null && !program.isClosed() && program.isUsedBy(this)) {
							program.release(this);
						}
					}
				}
			}
			catch (BridgeException e) {
				throw e;
			}
			catch (Exception e) {
				throw new BridgeException("import_failed",
					"Could not import " + source + ": " + e.getMessage(), e);
			}
		}
	}

	private void startAnalysis(Program program) {
		setRecoveryState(program, "running");
		Thread worker = new Thread(() -> {
			try {
				int transaction = program.startTransaction("AETHER: auto-analyze imported program");
				boolean commit = false;
				try {
					AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(program);
					manager.initializeOptions();
					manager.reAnalyzeAll(program.getMemory());
					manager.startAnalysis(TaskMonitor.DUMMY);
					GhidraProgramUtilities.markProgramAnalyzed(program);
					commit = true;
				}
				finally {
					program.endTransaction(transaction, commit);
				}
				RttiRecoveryRunner.run(project, program, TaskMonitor.DUMMY);
				saveProgram(program);
			}
			catch (Exception error) {
				setRecoveryState(program, "failed");
				DebugLog.debug(this, "import analysis failed: " + error.getMessage());
			}
		}, "aether-import-analysis");
		worker.setDaemon(true);
		worker.start();
	}

	private static void setRecoveryState(Program program, String state) {
		int transaction = program.startTransaction("AETHER: update recovery state");
		try {
			program.getOptions("AETHER").setString("rtti_import_recovery_state", state);
		}
		finally {
			program.endTransaction(transaction, true);
		}
	}

	private Map<String, Object> metadataFor(String programId) {
		synchronized (lock) {
			ProgramContext context = byId.get(programId);
			return context == null ? Map.of() : context.metadata();
		}
	}

	public Map<String, Object> invoke(String programId, String capability, Map<String, Object> arguments)
		throws Exception {
		ProgramContext context;
		synchronized (lock) {
			context = byId.get(programId);
		}
		if (context == null) {
			throw new BridgeException("program_closed", "Unknown or closed program: " + programId);
		}
		DebugLog.debug(this, "invoking capability program_id=" + programId + " capability=" + capability);

		// A per-program monitor prevents concurrent writes to one Program while allowing
		// requests for different open binaries to proceed independently.
			synchronized (context) {
			Object result = switch (capability) {				case "save_program" -> saveProgram(context.program());
				case "get_program_metadata" -> context.metadata();
				case "get_analysis_status" -> getAnalysisStatus(context.program(), programId);
				case "list_functions" -> listFunctions(context.program(), arguments);
				case "get_function_by_name" -> throw new BridgeException("invalid_identity",
					"Function names are discovery labels only; use a structured function address");
				case "resolve_pseudocode_call" -> resolvePseudocodeCall(context.program(), arguments);
				case "get_function" -> getFunction(context.program(), arguments);
				case "get_data_at_address" -> getDataAtAddress(context.program(), arguments);
				case "get_xrefs_to" -> getXrefsTo(context.program(), arguments);
				case "get_function_call_tree" -> getFunctionCallTree(context.program(), arguments);
				case "get_annotation_context" -> getAnnotationContext(context.program(), arguments);
				case "rename_function" -> renameFunction(context.program(), arguments);
				case "rename_variable" -> directAnnotationOperation(context.program(), arguments, "rename_variable");
				case "retype_variable" -> directAnnotationOperation(context.program(), arguments, "retype_variable");
				case "update_function_definition" -> directFunctionDefinition(context.program(), arguments);
				case "set_function_comment" -> setFunctionComment(context.program(), arguments);
				case "set_code_unit_comment" -> directAnnotationOperation(context.program(), arguments, "set_code_unit_comment");
				case "apply_annotation_batch" -> applyAnnotationBatch(context.program(), arguments);
				case "list_struct", "get_struct", "create_struct", "add_fields", "update_fields",
					"remove_fields", "resize_struct", "create_class", "update_class", "delete_class" ->
					StructureManager.invoke(context.program(), capability, arguments);
				default -> throw new BridgeException(
					"capability_unsupported", "Unsupported capability: " + capability);
			};
			if (GRAPH_AFFECTING_CAPABILITIES.contains(capability)) {
				// Function renames and signature updates are frozen into the stored
				// class graph (vtable slot contents); recompute it in the background.
				classGraphRefresher.schedule(context.program(), null);
			}
			@SuppressWarnings("unchecked")
			Map<String, Object> typedResult = (Map<String, Object>) result;
			return typedResult;
		}
	}

	/**
	 * Schedules a debounced class-graph recompute for the given Program. Used by
	 * the GUI plugin for change events; write capabilities schedule internally.
	 */
	public void scheduleClassGraphRefresh(Program program, Runnable onComplete) {
		classGraphRefresher.schedule(program, onComplete);
	}

	/** Propagates a rename already made by Ghidra's GUI through its verified virtual family. */
	public int propagateVirtualRename(Program program, Address address) throws Exception {
		if (program == null || address == null) {
			return 0;
		}
		Function target = program.getFunctionManager().getFunctionAt(address);
		if (target == null) {
			return 0;
		}
		List<Function> family = virtualFunctionFamily(program, target);
		if (family.size() <= 1) {
			return 0;
		}
		String name = target.getName();
		int transaction = program.startTransaction("AETHER: propagate virtual rename");
		boolean commit = false;
		try {
			for (Function member : family) {
				if (member != target && !name.equals(member.getName())) {
					member.setName(name, SourceType.USER_DEFINED);
				}
			}
			renameVtableFields(program, family, name);
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
		return family.size() - 1;
	}

	private Map<String, Object> getAnalysisStatus(Program program, String programId) {
		boolean isAnalyzing = AutoAnalysisManager.getAnalysisManager(program).isAnalyzing();
		boolean isAnalyzed = GhidraProgramUtilities.isAnalyzed(program);
		Map<String, Object> result = new LinkedHashMap<>();
		if (programId != null) {
			result.put("program_id", programId);
		}
		result.put("state", isAnalyzing ? "running" : isAnalyzed ? "completed" : "not_analyzed");
		result.put("is_analyzing", isAnalyzing);
		result.put("analyzed", isAnalyzed);
		result.put("analysis_job_id", programId == null ? null : "analysis-job-" + programId);
		Options aetherOptions = program.getOptions("AETHER");
		String rttiRecoveryState = aetherOptions.getString("rtti_import_recovery_state", null);
		if (rttiRecoveryState != null && !rttiRecoveryState.isBlank()) {
			result.put("rtti_recovery_state", rttiRecoveryState);
		}
		return result;
	}

	public void close() {
		// No Program is owned by this registry; save before dropping its identities.
		List<Program> programs;
		synchronized (lock) {
			programs = byId.values().stream().map(ProgramContext::program).toList();
		}
		for (Program program : programs) {
			try {
				saveProgram(program);
			}
			catch (RuntimeException error) {
				DebugLog.debug(this, "could not save Program during registry close: " + error.getMessage());
			}
		}
		for (Program program : List.copyOf(ownedPrograms)) {
			if (!program.isClosed() && program.isUsedBy(this)) {
				program.release(this);
			}
		}
		ownedPrograms.clear();
		classGraphRefresher.shutdown();
		synchronized (lock) {
			byId.clear();
			byProgram.clear();
		}
	}

	private static Map<String, Object> saveProgram(Program program) {
		try {
			if (program.isChanged()) {
				if (!program.canSave()) {
					throw new BridgeException("save_failed", "Modified Program cannot be saved: " + program.getName());
				}
				program.save("AETHER automatic session save", TaskMonitor.DUMMY);
			}
			if (program.isChanged()) {
				throw new BridgeException("save_failed", "Program remains modified after save: " + program.getName());
			}
			return Map.of("saved", true, "dirty", false);
		}
		catch (Exception error) {
			throw new BridgeException("save_failed", "Could not save Program: " + error.getMessage(), error);
		}
	}

	private Map<String, Object> listFunctions(Program program, Map<String, Object> arguments) {
		int limit = integerArgument(arguments, "limit", 50);
		if (limit < 1 || limit > 1000) {
			throw new BridgeException("invalid_argument", "limit must be between 1 and 1000");
		}
		String nameFilter = optionalString(arguments, "name");
		int offset = integerArgument(arguments, "offset", 0);
		if (offset < 0) {
			throw new BridgeException("invalid_argument", "offset must not be negative");
		}
		String patternText = optionalString(arguments, "pattern");
		boolean includeCallRelationships = Boolean.TRUE.equals(arguments.get("include_call_relationships"));
		Pattern pattern = null;
		if (patternText != null && !patternText.isBlank()) {
			try {
				pattern = Pattern.compile(patternText, Pattern.CASE_INSENSITIVE);
			}
			catch (PatternSyntaxException e) {
				throw new BridgeException("invalid_argument", "Invalid function pattern: " + e.getMessage());
			}
		}
		List<Map<String, Object>> functions = new ArrayList<>();
		List<Function> allFunctions = new ArrayList<>();
		Set<Address> seenFunctions = new HashSet<>();
		FunctionIterator iterator = program.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			Function function = iterator.next();
			if (seenFunctions.add(function.getEntryPoint())) {
				allFunctions.add(function);
			}
		}
		FunctionIterator externalIterator = program.getFunctionManager().getExternalFunctions();
		while (externalIterator.hasNext()) {
			Function function = externalIterator.next();
			if (seenFunctions.add(function.getEntryPoint())) {
				allFunctions.add(function);
			}
		}
		int matched = 0;
		for (Function function : allFunctions) {
			if (nameFilter != null && !function.getName().toLowerCase().contains(nameFilter.toLowerCase())) {
				continue;
			}
			if (pattern != null && !pattern.matcher(function.getName()).find()) {
				continue;
			}
			if (matched++ < offset || functions.size() >= limit) {
				continue;
			}
			Map<String, Object> item;
			if (!includeCallRelationships) {
				item = new LinkedHashMap<>();
				item.put("address", function.getEntryPoint() == null ? null : addressMap(function.getEntryPoint()));
				item.put("definition", function.getPrototypeString(false, false));
			}
			else {
				item = functionMap(function);
				item.put("size", function.getBody().getNumAddresses());
				item.put("library", function.isExternal() || function.getSymbol().getSource() == SourceType.DEFAULT && function.getName().startsWith("FUN_"));
				item.put("called_functions", calleesOf(program, function).stream().map(ProgramRegistry::functionMap).toList());
				item.put("caller_functions", callersOf(program, function).stream().map(ProgramRegistry::functionMap).toList());
			}
			functions.add(item);
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("functions", functions);
		result.put("returned", functions.size());
		result.put("total", matched);
		result.put("offset", offset);
		return result;
	}

	private Map<String, Object> getFunction(Program program, Map<String, Object> arguments) {
		Function function = functionAt(program, arguments);
		Map<String, Object> result = functionMap(function);
		Map<String, Object> pseudocode = getFunctionPseudocode(program, function,
			integerArgument(arguments, "timeout_seconds", 30), Boolean.TRUE.equals(arguments.get("read_only")));
		result.put("code", pseudocode.get("code"));
		result.put("calls", pseudocode.get("calls"));
		return result;
	}

	private Map<String, Object> getFunctionPseudocode(Program program, Function function, int timeout) {
		return getFunctionPseudocode(program, function, timeout, false);
	}

	private Map<String, Object> resolvePseudocodeCall(Program program, Map<String, Object> arguments) {
		Function caller = functionAt(program, Map.of("address", requiredArgument(arguments, "caller_address")));
		Address callSite = locationArgument(program, Map.of("address", requiredArgument(arguments, "call_site")));
		String displayName = optionalString(arguments, "display_name");
		Map<String, Object> pseudocode = getFunctionPseudocode(program, caller, 30, true);
		for (Map<String, Object> call : mapList(pseudocode.get("calls"))) {
			if (!Json.stringify(call.get("call_site")).equals(Json.stringify(addressMap(callSite)))) {
				continue;
			}
			if (displayName != null && !displayName.equals(call.get("name"))) {
				continue;
			}
			Map<String, Object> result = new LinkedHashMap<>(call);
			result.put("caller", functionMap(caller));
			return result;
		}
		throw new BridgeException("not_found", "No resolved pseudocode call at " + callSite);
	}

	private static List<Map<String, Object>> pseudocodeCalls(Program program, Function caller,
		DecompileResults results) {
		ClangTokenGroup markup = results.getCCodeMarkup();
		if (markup == null) {
			return List.of();
		}
		List<Map<String, Object>> calls = new ArrayList<>();
		Set<String> seen = new HashSet<>();
		Iterator<ClangToken> tokens = markup.tokenIterator(true);
		while (tokens.hasNext()) {
			ClangToken token = tokens.next();
			if (!(token instanceof ClangFuncNameToken functionToken)) {
				continue;
			}
			Address callSite = functionToken.getMinAddress();
			if (callSite == null) {
				continue;
			}
			Function target = calledFunctionAt(program, callSite);
			if (target == null) {
				continue;
			}
			String key = callSite + "\n" + target.getEntryPoint();
			if (!seen.add(key)) {
				continue;
			}
			Map<String, Object> call = new LinkedHashMap<>();
			call.put("call_site", addressMap(callSite));
			call.put("target_address", addressMap(target.getEntryPoint()));
			call.put("name", target.getName());
			calls.add(call);
		}
		return calls;
	}

	private static Function calledFunctionAt(Program program, Address callSite) {
		for (Reference reference : program.getReferenceManager().getReferencesFrom(callSite)) {
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Function target = program.getFunctionManager().getFunctionAt(reference.getToAddress());
			if (target == null) {
				target = program.getFunctionManager().getFunctionContaining(reference.getToAddress());
			}
			if (target != null) {
				return target;
			}
		}
		return null;
	}

	private Map<String, Object> getFunctionPseudocode(Program program, Function function, int timeout, boolean readOnly) {
		DecompInterface decompiler = new DecompInterface();
		try {
			if (!decompiler.openProgram(program)) {
				throw new BridgeException("decompilation_failed", decompiler.getLastMessage());
			}
			DecompileResults results = decompiler.decompileFunction(function, timeout, TaskMonitor.DUMMY);
			if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
				throw new BridgeException("decompilation_failed", results.getErrorMessage());
			}
			if (!readOnly) {
				commitDecompilerState(program, function, results.getHighFunction());
				results = decompiler.decompileFunction(function, timeout, TaskMonitor.DUMMY);
			}
			if (!results.decompileCompleted() || results.getDecompiledFunction() == null) {
				throw new BridgeException("decompilation_failed", results.getErrorMessage());
			}
			Map<String, Object> response = new LinkedHashMap<>();
			response.put("function", functionMap(function));
			response.put("signature", results.getDecompiledFunction().getSignature());
			response.put("code", addressedPseudocode(program, function, results));
			response.put("calls", pseudocodeCalls(program, function, results));
			response.put("variables", decompilerVariables(function, results));
			return response;
		}
		finally {
			decompiler.dispose();
		}
	}

	private static void commitDecompilerState(Program program, Function function, HighFunction highFunction) {
		if (highFunction == null) {
			return;
		}
		int transaction = program.startTransaction("AETHER: commit decompiler state");
		boolean commit = false;
		try {
			try {
				HighFunctionDBUtil.commitParamsToDatabase(highFunction, false,
					HighFunctionDBUtil.ReturnCommitOption.NO_COMMIT, function.getSignatureSource());
				HighFunctionDBUtil.commitLocalNamesToDatabase(highFunction, SourceType.USER_DEFINED);
			}
			catch (Exception error) {
				throw new BridgeException("decompilation_failed", "Could not commit decompiler state: " + error.getMessage(), error);
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	private Map<String, Object> getFunctionPseudocode(Program program, Function function) {
		return getFunctionPseudocode(program, function, 30);
	}

	private Map<String, Object> getDataAtAddress(Program program, Map<String, Object> arguments) {
		Address address = locationArgument(program, arguments);
		int count = integerArgument(arguments, "count", 16);
		if (count < 1 || count > 1024) {
			throw new BridgeException("invalid_argument", "count must be between 1 and 1024");
		}

		Map<String, Object> result = new LinkedHashMap<>();
		result.put("address", addressMap(address));
		result.put("ea", address.toString());
		result.put("name", nameAt(program, address));
		result.put("segment", segmentName(program, address));
		Function containing = program.getFunctionManager().getFunctionContaining(address);
		result.put("function_context", containing == null ? "outside_function" :
			"in_function:" + containing.getName() + "+0x" +
			Long.toHexString(address.getOffset() - containing.getEntryPoint().getOffset()));

		CodeUnit codeUnit = program.getListing().getCodeUnitContaining(address);
		result.put("item_kind", codeUnit instanceof Instruction ? "code" : codeUnit == null ? "unknown" : "data");
		result.put("item_head", codeUnit == null ? null : addressMap(codeUnit.getMinAddress()));
		result.put("item_end", codeUnit == null ? null : addressMap(codeUnit.getMaxAddress()));
		result.put("item_size", codeUnit == null ? 0 : codeUnit.getLength());
		result.put("disasm", instructionText(codeUnit));
		result.put("string", printableString(program, address, count));
		try {
			byte[] bytes = new byte[count];
			int read = program.getMemory().getBytes(address, bytes);
			result.put("bytes", toHex(bytes, read));
		}
		catch (MemoryAccessException e) {
			result.put("bytes", "Error reading bytes: " + e.getMessage());
		}
		return result;
	}

	private Map<String, Object> getXrefsTo(Program program, Map<String, Object> arguments) {
		Address address = locationArgument(program, arguments);
		Map<String, Object> target = new LinkedHashMap<>();
		target.put("address", addressMap(address));
		target.put("name", nameAt(program, address));
		List<Map<String, Object>> references = new ArrayList<>();
		ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
		while (iterator.hasNext()) {
			Reference reference = iterator.next();
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("from", addressMap(reference.getFromAddress()));
			item.put("type", reference.getReferenceType().toString());
			Function function = program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
			item.put("function", function == null ? Map.of("name", nameAt(program, reference.getFromAddress()),
				"address", addressMap(reference.getFromAddress())) : functionMap(function));
			references.add(item);
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("target", target);
		result.put("references", references);
		result.put("total", references.size());
		return result;
	}

	private Map<String, Object> getFunctionCallTree(Program program, Map<String, Object> arguments) {
		Function root = functionAt(program, arguments);
		if (root.isExternal() || root.isThunk()) {
			throw new BridgeException("unsupported", "External and thunk functions cannot be used as annotation roots");
		}
		int maxDepth = integerArgument(arguments, "max_depth", 5);
		int maxFunctions = integerArgument(arguments, "max_functions", 30);
		int maxEdges = integerArgument(arguments, "max_edges", 48);
		if (maxDepth < 0 || maxDepth > 10 || maxFunctions < 1 || maxFunctions > 500 || maxEdges < 1 || maxEdges > 2000) {
			throw new BridgeException("invalid_argument", "Invalid call-tree limits");
		}
		String direction = optionalString(arguments, "direction");
		if (direction == null || direction.isBlank()) {
			direction = "callees";
		}
		if (!direction.equals("callees") && !direction.equals("callers")) {
			throw new BridgeException("invalid_argument", "direction must be callers or callees");
		}

		List<Map<String, Object>> functions = new ArrayList<>();
		List<Map<String, Object>> edges = new ArrayList<>();
		List<Function> queueFunctions = new ArrayList<>();
		List<Integer> queueDepths = new ArrayList<>();
		Map<String, Integer> seen = new LinkedHashMap<>();
		queueFunctions.add(root);
		queueDepths.add(0);
		seen.put(root.getEntryPoint().toString(), 0);
		boolean truncated = false;
		for (int index = 0; index < queueFunctions.size(); index++) {
			Function current = queueFunctions.get(index);
			int depth = queueDepths.get(index);
			functions.add(functionMapWithDepth(current, depth));
			if (depth >= maxDepth) {
				continue;
			}
			List<Function> neighbors = direction.equals("callers")
				? callersOf(program, current) : calleesOf(program, current);
			for (Function neighbor : neighbors) {
				if (neighbor.isExternal() || neighbor.isThunk()) {
					continue;
				}
				if (edges.size() >= maxEdges) {
					truncated = true;
					break;
				}
				Map<String, Object> edge = new LinkedHashMap<>();
				edge.put("from", addressMap(direction.equals("callers") ? neighbor.getEntryPoint() : current.getEntryPoint()));
				edge.put("to", addressMap(direction.equals("callers") ? current.getEntryPoint() : neighbor.getEntryPoint()));
				edges.add(edge);
				String key = neighbor.getEntryPoint().toString();
				if (!seen.containsKey(key)) {
					if (queueFunctions.size() >= maxFunctions) {
						truncated = true;
						continue;
					}
					seen.put(key, depth + 1);
					queueFunctions.add(neighbor);
					queueDepths.add(depth + 1);
				}
			}
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("root", addressMap(root.getEntryPoint()));
		result.put("direction", direction);
		result.put("functions", functions);
		result.put("edges", edges);
		result.put("truncated", truncated);
		return result;
	}

	private List<Function> calleesOf(Program program, Function function) {
		List<Function> result = new ArrayList<>();
		Map<String, Boolean> seen = new LinkedHashMap<>();
		AddressIterator addresses = function.getBody().getAddresses(true);
		while (addresses.hasNext()) {
			for (Reference reference : program.getReferenceManager().getReferencesFrom(addresses.next())) {
				if (!reference.getReferenceType().isCall()) {
					continue;
				}
				Function target = program.getFunctionManager().getFunctionContaining(reference.getToAddress());
				if (target != null && target != function && seen.put(target.getEntryPoint().toString(), true) == null) {
					result.add(target);
				}
			}
		}
		return result;
	}

	private List<Function> callersOf(Program program, Function function) {
		List<Function> result = new ArrayList<>();
		Map<String, Boolean> seen = new LinkedHashMap<>();
		ReferenceIterator references = program.getReferenceManager().getReferencesTo(function.getEntryPoint());
		while (references.hasNext()) {
			Reference reference = references.next();
			if (!reference.getReferenceType().isCall()) {
				continue;
			}
			Function caller = program.getFunctionManager().getFunctionContaining(reference.getFromAddress());
			if (caller != null && caller != function && seen.put(caller.getEntryPoint().toString(), true) == null) {
				result.add(caller);
			}
		}
		return result;
	}

	private static Map<String, Object> functionMapWithDepth(Function function, int depth) {
		Map<String, Object> result = new LinkedHashMap<>(functionMap(function));
		result.put("depth", depth);
		return result;
	}

	private Map<String, Object> getAnnotationContext(Program program, Map<String, Object> arguments) {
		Object rawFunctions = arguments.get("functions");
		if (!(rawFunctions instanceof List<?> requested)) {
			throw new BridgeException("invalid_argument", "functions must be an array");
		}
		List<Map<String, Object>> resultFunctions = new ArrayList<>();
		for (Object raw : requested) {
			Map<String, Object> item = Json.object(raw);
			Map<String, Object> lookup = new LinkedHashMap<>();
			Object address = item.get("address");
			if (address == null) {
				throw new BridgeException("invalid_identity", "Each function requires a structured address");
			}
			lookup.put("address", address);
			Function function = functionAt(program, lookup);
			if (function.isExternal() || function.isThunk()) {
				continue;
			}
			Map<String, Object> entry = new LinkedHashMap<>(functionMap(function));
			Map<String, Object> pseudocode = getFunctionPseudocode(program, function);
			entry.put("pseudocode", pseudocode.get("code"));
			entry.put("variables", pseudocode.get("variables"));
			List<Map<String, Object>> codeUnits = new ArrayList<>();
			InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
			while (instructions.hasNext() && codeUnits.size() < 256) {
				Instruction instruction = instructions.next();
				Map<String, Object> codeUnit = new LinkedHashMap<>();
				codeUnit.put("address", addressMap(instruction.getAddress()));
				codeUnit.put("mnemonic", instruction.getMnemonicString());
				codeUnit.put("eol", commentOrEmpty(instruction, CodeUnit.EOL_COMMENT));
				codeUnit.put("pre", commentOrEmpty(instruction, CodeUnit.PRE_COMMENT));
				codeUnit.put("post", commentOrEmpty(instruction, CodeUnit.POST_COMMENT));
				codeUnit.put("plate", commentOrEmpty(instruction, CodeUnit.PLATE_COMMENT));
				codeUnit.put("repeatable", commentOrEmpty(instruction, CodeUnit.REPEATABLE_COMMENT));
				codeUnits.add(codeUnit);
			}
			entry.put("code_units", codeUnits);
			resultFunctions.add(entry);
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("functions", resultFunctions);
		return result;
	}

	private static String commentOrEmpty(CodeUnit codeUnit, int commentType) {
		String comment = codeUnit.getComment(commentType);
		return comment == null ? "" : comment;
	}

	private static List<Map<String, Object>> decompilerVariables(Function function, DecompileResults results) {
		Map<String, Map<String, Object>> variables = new LinkedHashMap<>();
		for (Variable variable : function.getAllVariables()) {
			boolean autoParameter = variable instanceof Parameter parameter && parameter.isAutoParameter();
			addVariable(variables, variable.getName(), variable instanceof Parameter, autoParameter,
				variable.getDataType(), variable.getVariableStorage());
		}
		HighFunction highFunction = results.getHighFunction();
		if (highFunction != null) {
			LocalSymbolMap symbols = highFunction.getLocalSymbolMap();
			for (Iterator<HighSymbol> iterator = symbols.getSymbols(); iterator.hasNext();) {
				HighSymbol symbol = iterator.next();
				if (symbol.isGlobal() || symbol.getName() == null || symbol.getName().isBlank() ||
					symbol.getStorage() == null) {
					continue;
				}
				boolean autoParameter = symbol.getStorage().getAutoParameterType() != null;
				addVariable(variables, symbol.getName(), symbol.isParameter(), autoParameter,
					symbol.getDataType(), symbol.getStorage());
			}
		}
		return new ArrayList<>(variables.values());
	}

	private static void addVariable(Map<String, Map<String, Object>> variables, String name,
		boolean parameter, boolean autoParameter, DataType dataType, VariableStorage storage) {
		Map<String, Object> variable = new LinkedHashMap<>();
		variable.put("name", name);
		variable.put("parameter", parameter);
		variable.put("auto_parameter", autoParameter);
		variable.put("data_type", dataType == null ? "" : dataType.getDisplayName());
		if (storage != null) {
			variable.put("storage", storage.toString());
			variable.put("storage_serialization", storage.getSerializationString());
		}
		variables.putIfAbsent(name, variable);
	}

	private String addressedPseudocode(Program program, Function function, DecompileResults results) {
		Map<String, List<CodeComment>> commentsByAddress = instructionComments(program, function);
		ClangTokenGroup markup = results.getCCodeMarkup();
		if (markup == null) {
			return "";
		}

		Map<ClangLine, Map<String, Address>> addressesByLine = new LinkedHashMap<>();
		Map<Integer, ClangLine> linesByNumber = new LinkedHashMap<>();
		Iterator<ClangToken> tokens = markup.tokenIterator(true);
		while (tokens.hasNext()) {
			ClangToken token = tokens.next();
			ClangLine line = token.getLineParent();
			if (line == null) {
				continue;
			}
			linesByNumber.put(line.getLineNumber(), line);
			Address address = token.getMinAddress();
			if (address != null) {
				addressesByLine.computeIfAbsent(line, ignored -> new LinkedHashMap<>())
					.putIfAbsent(address.toString(), address);
			}
		}

		List<ClangLine> lines = new ArrayList<>(linesByNumber.values());
		lines.sort(Comparator.comparingInt(ClangLine::getLineNumber));
		StringBuilder output = new StringBuilder();
		Set<String> emittedComments = new HashSet<>();
		for (ClangLine line : lines) {
			Map<String, Address> addresses = addressesByLine.getOrDefault(line, Map.of());
			if (addresses.isEmpty()) {
				output.append(renderedLine(line)).append('\n');
				continue;
			}
			String prefix = addresses.values().stream()
				.map(ProgramRegistry::displayAddress)
				.reduce((left, right) -> left + ", " + right).orElse(displayAddress(function.getEntryPoint()));
			String rendered = renderedLine(line);
			List<String> commentsAfter = new ArrayList<>();
			for (Address address : addresses.values()) {
				List<CodeComment> comments = commentsByAddress.get(address.toString());
				if (comments == null) {
					continue;
				}
				for (CodeComment comment : comments) {
					String commentKey = commentKey(address, comment);
					if (emittedComments.contains(commentKey)) {
						continue;
					}
					if (rendered.contains(comment.text())) {
						emittedComments.add(commentKey);
						continue;
					}
					if ("eol".equals(comment.kind())) {
						rendered = appendEndOfLineComment(rendered, comment.text());
					}
					else if ("post".equals(comment.kind())) {
						commentsAfter.add(comment.text());
					}
					else {
						appendStandaloneComment(output, displayAddress(address), comment.text());
					}
					emittedComments.add(commentKey);
				}
			}
			output.append(prefix).append(": ").append(rendered).append('\n');
			for (String comment : commentsAfter) {
				appendStandaloneComment(output, prefix.split(", ")[0], comment);
			}
		}
		for (Map.Entry<String, List<CodeComment>> entry : commentsByAddress.entrySet()) {
			for (CodeComment comment : entry.getValue()) {
				if (!emittedComments.contains(commentKey(entry.getKey(), comment))) {
					appendStandaloneComment(output, displayAddress(entry.getKey()), comment.text());
					emittedComments.add(commentKey(entry.getKey(), comment));
				}
			}
		}
		String functionComment = function.getComment();
		if (functionComment != null && !functionComment.isBlank() &&
			!commentAppears(output.toString(), functionComment)) {
			StringBuilder withFunctionComment = new StringBuilder();
			appendUnaddressedComment(withFunctionComment, functionComment);
			withFunctionComment.append(output);
			return withFunctionComment.toString();
		}
		return output.toString();
	}

	private static String renderedLine(ClangLine line) {
		StringBuilder output = new StringBuilder(line.getIndentString());
		for (ClangToken token : line.getAllTokens()) {
			output.append(token.getText());
		}
		return output.toString();
	}

	private record CodeComment(String kind, String text) {
	}

	private static Map<String, List<CodeComment>> instructionComments(Program program, Function function) {
		Map<String, List<CodeComment>> comments = new LinkedHashMap<>();
		InstructionIterator instructions = program.getListing().getInstructions(function.getBody(), true);
		while (instructions.hasNext() && comments.size() < 256) {
			Instruction instruction = instructions.next();
			addComment(comments, instruction, CodeUnit.EOL_COMMENT, "eol");
			addComment(comments, instruction, CodeUnit.PRE_COMMENT, "pre");
			addComment(comments, instruction, CodeUnit.POST_COMMENT, "post");
			addComment(comments, instruction, CodeUnit.PLATE_COMMENT, "plate");
			addComment(comments, instruction, CodeUnit.REPEATABLE_COMMENT, "repeatable");
		}
		return comments;
	}

	private static void addComment(Map<String, List<CodeComment>> comments, CodeUnit codeUnit, int type, String kind) {
		String comment = codeUnit.getComment(type);
		if (comment != null && !comment.isBlank()) {
			comments.computeIfAbsent(codeUnit.getMinAddress().toString(), ignored -> new ArrayList<>())
				.add(new CodeComment(kind, comment));
		}
	}

	private static String appendEndOfLineComment(String line, String comment) {
		String[] parts = comment.split("\\R", -1);
		StringBuilder result = new StringBuilder(line).append(" /* ").append(parts[0]).append(" */");
		for (int index = 1; index < parts.length; index++) {
			result.append(" /* ").append(parts[index]).append(" */");
		}
		return result.toString();
	}

	private static void appendStandaloneComment(StringBuilder output, String address, String text) {
		String value = text;
		for (String line : value.split("\\R", -1)) {
			output.append(address).append(": /* ").append(line).append(" */\n");
		}
	}

	private static void appendUnaddressedComment(StringBuilder output, String text) {
		for (String line : text.split("\\R", -1)) {
			output.append("/* ").append(line).append(" */\n");
		}
	}

	private static boolean commentAppears(String output, String comment) {
		for (String line : comment.split("\\R")) {
			if (!line.isBlank() && output.contains(line.trim())) {
				return true;
			}
		}
		return false;
	}

	private static String commentKey(Address address, CodeComment comment) {
		return commentKey(address.toString(), comment);
	}

	private static String commentKey(String address, CodeComment comment) {
		return address + ":" + comment.kind() + ":" + comment.text();
	}

	private static String displayAddress(Address address) {
		return "0x" + Long.toUnsignedString(address.getOffset(), 16);
	}

	private static String displayAddress(String address) {
		int separator = address.indexOf(':');
		return "0x" + (separator >= 0 ? address.substring(separator + 1) : address);
	}

	private Map<String, Object> applyAnnotationBatch(Program program, Map<String, Object> arguments) {
		Object rawOperations = arguments.get("operations");
		if (!(rawOperations instanceof List<?> operations) || operations.isEmpty()) {
			throw new BridgeException("invalid_argument", "operations must be a non-empty array");
		}
		List<Map<String, Object>> prepared = new ArrayList<>();
		Set<String> targets = new HashSet<>();
		Map<String, DecompilerContext> decompilerContexts = new LinkedHashMap<>();
		String batchId = "batch-" + UUID.randomUUID();
		int transaction = program.startTransaction("AETHER: apply annotation batch");
		boolean commit = false;
		try {
			for (Object raw : operations) {
				Map<String, Object> operation = Json.object(raw);
				Map<String, Object> item = prepareAnnotationOperation(program, operation, decompilerContexts);
				String targetKey = item.get("kind") + ":" + Json.stringify(item.get("target"));
				if (!targets.add(targetKey)) {
					throw new BridgeException("annotation_conflict", "Multiple operations target the same value");
				}
				prepared.add(item);
			}
			for (Map<String, Object> operation : prepared) {
				applyPreparedAnnotation(program, operation);
			}
			commit = true;
		}
		finally {
			program.endTransaction(transaction, commit);
			for (DecompilerContext context : decompilerContexts.values()) {
				context.decompiler().dispose();
			}
		}
		List<Map<String, Object>> applied = new ArrayList<>();
		for (Map<String, Object> operation : prepared) {
			Map<String, Object> result = new LinkedHashMap<>();
			result.put("id", operation.get("id"));
			result.put("kind", operation.get("kind"));
			result.put("target", operation.get("target"));
			result.put("before", operation.get("before"));
			result.put("after", operation.get("after"));
			result.put("comment_kind", operation.get("comment_kind"));
			result.put("created_decompiler_variable", operation.get("created_decompiler_variable"));
			result.put("vtable_fields", operation.get("vtable_fields"));
			applied.add(result);
		}
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("batch_id", batchId);
		result.put("operations", applied);
		return result;
	}

	private Map<String, Object> prepareAnnotationOperation(Program program, Map<String, Object> operation,
		Map<String, DecompilerContext> decompilerContexts) {
		String kind = Json.string(operation, "kind");
		String after = Json.string(operation, "value");
		Map<String, Object> target = Json.object(operation.get("target"));
		Map<String, Object> prepared = new LinkedHashMap<>(operation);
		prepared.put("target", target);
		prepared.put("after", after);
		String before;
		switch (kind) {
			case "rename_function" -> {
				Function function = functionAt(program, Map.of("address", target.get("function_address")));
				before = function.getName();
				prepared.put("function", function);
			}
			case "set_function_comment" -> {
				Function function = functionAt(program, Map.of("address", target.get("function_address")));
				before = function.getComment() == null ? "" : function.getComment();
				prepared.put("function", function);
			}
			case "set_code_unit_comment" -> {
				Address address = addressValue(program, target.get("address"));
				CodeUnit codeUnit = program.getListing().getCodeUnitContaining(address);
				if (codeUnit == null) {
					throw new BridgeException("not_found", "No code unit at " + address);
				}
				int commentType = commentType(Json.string(operation, "comment_kind"));
				before = codeUnit.getComment(commentType) == null ? "" : codeUnit.getComment(commentType);
				prepared.put("code_unit", codeUnit);
				prepared.put("comment_type", commentType);
			}
			case "rename_variable" -> {
				Function function = functionAt(program, Map.of("address", target.get("function_address")));
				Variable variable = findVariable(function, optionalString(target, "variable_name"));
				prepared.put("function", function);
				if (Boolean.TRUE.equals(operation.get("remove_decompiler_variable"))) {
					if (variable == null) {
						throw new BridgeException("not_found", "Variable not found in function " + function.getName());
					}
					before = variable.getName();
					prepared.put("variable", variable);
				}
				else if (variable != null) {
					if (variable instanceof Parameter parameter && parameter.isAutoParameter()) {
						throw new BridgeException("unsupported", "Auto-parameter cannot be renamed: " + variable.getName());
					}
					before = variable.getName();
					prepared.put("variable", variable);
				}
				else {
					DecompilerVariable decompilerVariable = findDecompilerVariable(program, function,
						optionalString(target, "variable_name"), decompilerContexts);
					if (decompilerVariable == null) {
						throw new BridgeException("not_found", "Variable not found in function " + function.getName());
					}
					if (decompilerVariable.symbol().getStorage().getAutoParameterType() != null) {
						throw new BridgeException("unsupported", "Auto-parameter cannot be renamed: " + decompilerVariable.before());
					}
					before = decompilerVariable.before();
					prepared.put("decompiler_variable", true);
					prepared.put("created_decompiler_variable", decompilerVariable.created());
					prepared.put("high_symbol", decompilerVariable.symbol());
				}
			}
			case "retype_variable" -> {
				Function function = functionAt(program, Map.of("address", target.get("function_address")));
				Variable variable = findVariable(function, optionalString(target, "variable_name"));
				if (variable == null) {
					throw new BridgeException("not_found", "Variable not found in function " + function.getName());
				}
				DataType dataType = parseDataType(program, after);
				before = variable.getDataType().getDisplayName();
				prepared.put("function", function);
				prepared.put("variable", variable);
				prepared.put("data_type", dataType);
			}
			case "update_function_definition" -> {
				Function function = functionAt(program, Map.of("address", target.get("function_address")));
				if (function.isExternal() || function.isThunk()) {
					throw new BridgeException("unsupported", "External and thunk functions cannot be redefined");
				}
				FunctionDefinitionPreparation definition = prepareFunctionDefinition(program, function, after);
				before = Json.stringify(canonicalCurrentDefinition(function));
				prepared.put("function", function);
				prepared.put("return_type", definition.returnType());
				prepared.put("parameters", definition.parameters());
				prepared.put("update_type", definition.updateType());
				prepared.put("varargs", definition.varargs());
				prepared.put("after", Json.stringify(definition.canonical()));
			}
			default -> throw new BridgeException("invalid_argument", "Unsupported annotation operation: " + kind);
		}
		Object expected = operation.get("expected_before");
		if (expected != null && !String.valueOf(expected).equals(before)) {
			throw new BridgeException("annotation_conflict", "Annotation target changed before apply");
		}
		prepared.put("before", before);
		return prepared;
	}

	@SuppressWarnings("unchecked")
	private static void applyPreparedAnnotation(Program program, Map<String, Object> operation) {
		String kind = String.valueOf(operation.get("kind"));
		String after = String.valueOf(operation.get("after"));
		switch (kind) {
			case "rename_function" -> {
				try {
					Function function = (Function) operation.get("function");
					function.setName(after, SourceType.USER_DEFINED);
					List<Map<String, Object>> restoreFields = mapList(operation.get("restore_vtable_fields"));
					operation.put("vtable_fields", restoreFields.isEmpty()
						? renameVtableFields(program, List.of(function), after)
						: restoreVtableFields(program, restoreFields));
				}
				catch (Exception e) {
					throw new BridgeException("annotation_failed", "Could not rename function: " + e.getMessage(), e);
				}
			}
			case "set_function_comment" -> ((Function) operation.get("function"))
				.setComment(after.isBlank() ? null : after);
			case "set_code_unit_comment" -> ((CodeUnit) operation.get("code_unit"))
				.setComment((Integer) operation.get("comment_type"), after.isBlank() ? null : after);
			case "rename_variable" -> {
				try {
					if (Boolean.TRUE.equals(operation.get("remove_decompiler_variable"))) {
						((Function) operation.get("function")).removeVariable((Variable) operation.get("variable"));
					}
					else if (!Boolean.TRUE.equals(operation.get("decompiler_variable"))) {
						((Variable) operation.get("variable")).setName(after, SourceType.USER_DEFINED);
					}
					else {
						HighSymbol symbol = (HighSymbol) operation.get("high_symbol");
						HighFunctionDBUtil.updateDBVariable(symbol, after, symbol.getDataType(), SourceType.USER_DEFINED);
					}
				}
				catch (Exception e) {
					throw new BridgeException("annotation_failed", "Could not update variable: " + e.getMessage(), e);
				}
			}
			case "retype_variable" -> {
				try {
					((Variable) operation.get("variable")).setDataType(
						(DataType) operation.get("data_type"), SourceType.USER_DEFINED);
				}
				catch (Exception e) {
					throw new BridgeException("annotation_failed", "Could not retype variable: " + e.getMessage(), e);
				}
			}
			case "update_function_definition" -> {
				try {
					Function function = (Function) operation.get("function");
					function.updateFunction(function.getCallingConventionName(),
						new ReturnParameterImpl((DataType) operation.get("return_type"), function.getProgram()),
						(List<ParameterImpl>) operation.get("parameters"),
						(FunctionUpdateType) operation.get("update_type"), true, SourceType.USER_DEFINED);
					function.setVarArgs(Boolean.TRUE.equals(operation.get("varargs")));
				}
				catch (Exception e) {
					throw new BridgeException("annotation_failed", "Could not update function definition: " + e.getMessage(), e);
				}
			}
			default -> throw new BridgeException("invalid_argument", "Unsupported annotation operation: " + kind);
		}
	}

	private static Variable findVariable(Function function, String name) {
		Variable match = null;
		for (Variable variable : function.getAllVariables()) {
			if (name == null || name.equals(variable.getName())) {
				if (match != null) {
					throw new BridgeException("ambiguous_variable", "Multiple variables match the annotation target");
				}
				match = variable;
			}
		}
		if (match == null) {
			return null;
		}
		return match;
	}

	private static DataType parseDataType(Program program, String specification) {
		if (specification == null || specification.isBlank()) {
			throw new BridgeException("invalid_argument", "data_type must not be blank");
		}
		try {
			if (specification.startsWith("/")) {
				int separator = specification.lastIndexOf('/');
				if (separator <= 0 || separator == specification.length() - 1) {
					throw new BridgeException("invalid_data_type", "Invalid data type path: " + specification);
				}
				DataType dataType = program.getDataTypeManager().getDataType(new DataTypePath(
					specification.substring(0, separator), specification.substring(separator + 1)));
				if (dataType == null) {
					throw new BridgeException("invalid_data_type", "Data type not found: " + specification);
				}
				return dataType;
			}
			DataTypeParser parser = new DataTypeParser(program.getDataTypeManager(),
				program.getDataTypeManager(), null, DataTypeParser.AllowedDataTypes.ALL);
			return parser.parse(specification.trim());
		}
		catch (Exception e) {
			throw new BridgeException("invalid_data_type", "Could not parse data type '" + specification + "': " + e.getMessage(), e);
		}
	}

	private static FunctionDefinitionPreparation prepareFunctionDefinition(
		Program program, Function function, String encodedDefinition) {
		Map<String, Object> definition;
		try {
			definition = Json.object(Json.parse(encodedDefinition));
		}
		catch (RuntimeException e) {
			throw new BridgeException("invalid_argument", "Function definition must be a JSON object", e);
		}
		DataType returnType = parseDataType(program, Json.string(definition, "return_type"));
		Object rawParameters = definition.get("parameters");
		if (!(rawParameters instanceof List<?> requested)) {
			throw new BridgeException("invalid_argument", "parameters must be an array");
		}
		Parameter[] existing = function.getParameters();
		int autoCount = function.getAutoParameterCount();
		List<Map<String, Object>> effective = new ArrayList<>();
		int cursor = 0;
		for (int index = 0; index < autoCount; index++) {
			Map<String, Object> item = null;
			if (cursor < requested.size()) {
				Map<String, Object> candidate = Json.object(requested.get(cursor));
				if (existing[index].getName().equals(candidate.get("name"))) {
					item = new LinkedHashMap<>(candidate);
					cursor++;
				}
			}
			if (item == null) {
				item = new LinkedHashMap<>();
				item.put("name", existing[index].getName());
				item.put("data_type", existing[index].getDataType().getDisplayName());
				VariableStorage storage = existing[index].getVariableStorage();
				if (storage != null && !storage.isUnassignedStorage()) {
					item.put("storage", Map.of("serialization", storage.getSerializationString()));
				}
			}
			effective.add(item);
		}
		while (cursor < requested.size()) {
			effective.add(new LinkedHashMap<>(Json.object(requested.get(cursor++))));
		}
		List<Map<String, Object>> normalized = new ArrayList<>();
		List<ParameterImpl> parameters = new ArrayList<>();
		boolean customStorage = false;
		for (Object raw : requested) {
			if (Json.object(raw).containsKey("storage")) {
				customStorage = true;
			}
		}
		for (Map<String, Object> item : effective) {
			String name = Json.string(item, "name");
			String type = Json.string(item, "data_type");
			Map<String, Object> normalizedItem = new LinkedHashMap<>();
			normalizedItem.put("name", name);
			normalizedItem.put("data_type", parseDataType(program, type).getDisplayName());
			normalized.add(normalizedItem);
		}
		Set<String> names = new HashSet<>();
		for (int index = 0; index < effective.size(); index++) {
			Map<String, Object> item = effective.get(index);
			String name = Json.string(item, "name");
			if (!names.add(name)) {
				throw new BridgeException("invalid_argument", "Duplicate parameter name: " + name);
			}
			DataType dataType = parseDataType(program, Json.string(item, "data_type"));
			if (index < autoCount) {
				Parameter auto = existing[index];
				if (!name.equals(auto.getName())) {
					throw new BridgeException("unsupported", "Auto-parameters cannot be renamed");
				}
				VariableStorage autoStorage = auto.getVariableStorage();
				Object rawStorage = item.get("storage");
				if (customStorage && autoStorage == null) {
					throw new BridgeException("invalid_argument", "Auto-parameter storage is required for custom storage");
				}
				if (rawStorage != null && autoStorage != null &&
					!parseStorage(program, rawStorage, dataType.getLength()).equals(autoStorage)) {
					throw new BridgeException("unsupported", "Auto-parameter storage cannot be changed");
				}
				try {
					ParameterImpl parameter = new ParameterImpl(auto, program);
					if (!dataType.isEquivalent(auto.getDataType())) {
						parameter.setDataType(dataType, SourceType.USER_DEFINED);
					}
					parameters.add(parameter);
					if (customStorage && autoStorage != null) {
						normalized.get(index).put("storage", Map.of("serialization", autoStorage.getSerializationString()));
					}
				}
				catch (Exception e) {
					throw new BridgeException("invalid_argument", "Could not update auto-parameter '" + name + "': " + e.getMessage(), e);
				}
				continue;
			}
			Object rawStorage = item.get("storage");
			VariableStorage storage = rawStorage == null ? null : parseStorage(program, rawStorage, dataType.getLength());
			if (customStorage && storage == null) {
				throw new BridgeException("invalid_argument", "Every parameter needs storage when custom storage is used");
			}
			ParameterImpl parameter;
			try {
				parameter = storage == null
					? new ParameterImpl(name, dataType, program, SourceType.USER_DEFINED)
					: new ParameterImpl(name, dataType, storage, program, SourceType.USER_DEFINED);
			}
			catch (Exception e) {
				throw new BridgeException("invalid_argument", "Could not construct parameter '" + name + "': " + e.getMessage(), e);
			}
			parameters.add(parameter);
			if (customStorage && storage != null) {
				normalized.get(index).put("storage", Map.of("serialization", storage.getSerializationString()));
			}
		}
		for (int left = 0; left < parameters.size(); left++) {
			VariableStorage leftStorage = parameters.get(left).getVariableStorage();
			if (leftStorage == null || leftStorage.isUnassignedStorage()) {
				continue;
			}
			for (int right = left + 1; right < parameters.size(); right++) {
				VariableStorage rightStorage = parameters.get(right).getVariableStorage();
				if (rightStorage != null && !rightStorage.isUnassignedStorage() && leftStorage.intersects(rightStorage)) {
					throw new BridgeException("invalid_storage", "Parameter storage overlaps between " +
						parameters.get(left).getName() + " and " + parameters.get(right).getName());
				}
			}
		}
		boolean varargs = Boolean.TRUE.equals(definition.get("varargs"));
		FunctionUpdateType updateType = customStorage ? FunctionUpdateType.CUSTOM_STORAGE :
			FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS;
			return new FunctionDefinitionPreparation(returnType, parameters, updateType,
				varargs, canonicalDefinition(function, returnType, normalized, varargs, customStorage));
	}

	private static Map<String, Object> canonicalDefinition(Function function, DataType returnType,
		List<Map<String, Object>> parameters, boolean varargs, boolean customStorage) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("return_type", returnType.getDisplayName());
		result.put("calling_convention", function.getCallingConventionName());
		result.put("custom_storage", customStorage);
		result.put("parameters", parameters);
		result.put("varargs", varargs);
		return result;
	}

	private static Map<String, Object> canonicalCurrentDefinition(Function function) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("return_type", function.getReturnType().getDisplayName());
		result.put("calling_convention", function.getCallingConventionName());
		result.put("custom_storage", function.hasCustomVariableStorage());
		List<Map<String, Object>> parameters = new ArrayList<>();
		for (Parameter parameter : function.getParameters()) {
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("name", parameter.getName());
			item.put("data_type", parameter.getDataType().getDisplayName());
			if (function.hasCustomVariableStorage()) {
				item.put("storage", Map.of("serialization", parameter.getVariableStorage().getSerializationString()));
			}
			parameters.add(item);
		}
		result.put("parameters", parameters);
		result.put("varargs", function.hasVarArgs());
		return result;
	}

	private static VariableStorage parseStorage(Program program, Object raw, int defaultSize) {
		if (raw instanceof String serialization) {
			try {
				return VariableStorage.deserialize(program, serialization);
			}
			catch (Exception e) {
				throw new BridgeException("invalid_storage", "Invalid storage serialization: " + e.getMessage(), e);
			}
		}
		Map<String, Object> storage = Json.object(raw);
		if (storage.get("serialization") instanceof String serialization) {
			return parseStorage(program, serialization, defaultSize);
		}
		try {
			if (storage.get("register") instanceof String registerName) {
				Register register = program.getRegister(registerName);
				if (register == null) {
					throw new BridgeException("invalid_storage", "Unknown register: " + registerName);
				}
				return new VariableStorage(program, register);
			}
			if (storage.containsKey("stack_offset")) {
				long offset = longValue(storage.get("stack_offset"));
				int size = storage.containsKey("size") ? (int) longValue(storage.get("size")) : defaultSize;
				if (size <= 0) {
					throw new BridgeException("invalid_storage", "Stack storage requires a positive size");
				}
				return new VariableStorage(program, program.getCompilerSpec().getStackSpace().getAddress(offset), size);
			}
			Object rawPieces = storage.get("pieces");
			if (rawPieces instanceof List<?> pieces && !pieces.isEmpty()) {
				List<Varnode> varnodes = new ArrayList<>();
				for (Object rawPiece : pieces) {
					Map<String, Object> piece = Json.object(rawPiece);
					int size = (int) longValue(piece.get("size"));
					if (size <= 0) {
						throw new BridgeException("invalid_storage", "Storage pieces require positive sizes");
					}
					if (piece.get("register") instanceof String registerName) {
						Register register = program.getRegister(registerName);
						if (register == null) {
							throw new BridgeException("invalid_storage", "Unknown register: " + registerName);
						}
						varnodes.add(new Varnode(register.getAddress(), size));
					}
					else if (piece.containsKey("stack_offset")) {
						varnodes.add(new Varnode(program.getCompilerSpec().getStackSpace().getAddress(
							longValue(piece.get("stack_offset"))), size));
					}
					else {
						throw new BridgeException("invalid_storage", "Each storage piece needs register or stack_offset");
					}
				}
				return new VariableStorage(program, varnodes.toArray(Varnode[]::new));
			}
		}
		catch (BridgeException e) {
			throw e;
		}
		catch (Exception e) {
			throw new BridgeException("invalid_storage", "Could not construct variable storage: " + e.getMessage(), e);
		}
		throw new BridgeException("invalid_storage", "Storage requires serialization, register, stack_offset, or pieces");
	}

	private static long longValue(Object value) {
		if (value instanceof Number number) {
			return number.longValue();
		}
		try {
			return Long.decode(String.valueOf(value));
		}
		catch (NumberFormatException e) {
			throw new BridgeException("invalid_storage", "Expected a numeric storage offset or size");
		}
	}

	private static DecompilerVariable findDecompilerVariable(Program program, Function function,
		String name, Map<String, DecompilerContext> decompilerContexts) {
		String functionKey = function.getEntryPoint().toString();
		DecompilerContext context = decompilerContexts.get(functionKey);
		if (context == null) {
			DecompInterface decompiler = new DecompInterface();
			if (!decompiler.openProgram(program)) {
				decompiler.dispose();
				return null;
			}
			DecompileResults results = decompiler.decompileFunction(function, 30, TaskMonitor.DUMMY);
			if (!results.decompileCompleted() || results.getHighFunction() == null) {
				decompiler.dispose();
				return null;
			}
			context = new DecompilerContext(decompiler, results.getHighFunction());
			decompilerContexts.put(functionKey, context);
		}
		HighSymbol match = null;
		LocalSymbolMap symbols = context.highFunction().getLocalSymbolMap();
		for (Iterator<HighSymbol> iterator = symbols.getSymbols(); iterator.hasNext();) {
				HighSymbol symbol = iterator.next();
				if (symbol.isGlobal() || (name != null && !name.equals(symbol.getName())) || symbol.getStorage() == null) {
					continue;
				}
				if (match != null) {
					throw new BridgeException("ambiguous_variable", "Multiple decompiler variables match the annotation target");
				}
				match = symbol;
			}
			if (match == null) {
				return null;
			}
			String before = match.getName();
			boolean created = HighFunctionDBUtil.getFunctionVariable(match) == null;
			return new DecompilerVariable(before, created, match);
	}

	private record DecompilerContext(DecompInterface decompiler, HighFunction highFunction) {
	}

	private record DecompilerVariable(String before, boolean created, HighSymbol symbol) {
	}

	private record FunctionDefinitionPreparation(DataType returnType, List<ParameterImpl> parameters,
		FunctionUpdateType updateType, boolean varargs, Map<String, Object> canonical) {
	}

	private static int commentType(String value) {
		return switch (value.toLowerCase()) {
			case "eol" -> CodeUnit.EOL_COMMENT;
			case "pre" -> CodeUnit.PRE_COMMENT;
			case "post" -> CodeUnit.POST_COMMENT;
			case "plate" -> CodeUnit.PLATE_COMMENT;
			case "repeatable" -> CodeUnit.REPEATABLE_COMMENT;
			default -> throw new BridgeException("invalid_argument", "Unknown comment kind: " + value);
		};
	}

	private static Address addressValue(Program program, Object value) {
		return locationArgument(program, Map.of("address", value));
	}

	/**
	 * Renames the exact function. A name containing "::" is split on the last
	 * "::": the prefix becomes a hierarchically resolved or created namespace
	 * path ("Sexy::Fish::update" places `update` in namespace Sexy::Fish) and
	 * the suffix becomes the function name. A plain name keeps the current
	 * parent namespace.
	 */
	private Map<String, Object> renameFunction(Program program, Map<String, Object> arguments)
		throws Exception {
		String name = Json.string(arguments, "name");
		if (name.isBlank()) {
			throw new BridgeException("invalid_argument", "name must not be blank");
		}
		Function function = functionAt(program, arguments);
		List<Function> family = Boolean.FALSE.equals(arguments.get("propagate_virtual"))
			? List.of(function) : virtualFunctionFamily(program, function);
		List<Map<String, Object>> before = new ArrayList<>();
		for (Function member : family) {
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("address", addressMap(member.getEntryPoint()));
			item.put("before", qualifiedFunctionName(member));
			before.add(item);
		}
		String delimiter = Namespace.NAMESPACE_DELIMITER;
		int separator = name.lastIndexOf(delimiter);
		int transaction = program.startTransaction("AETHER: rename function");
		boolean commit = false;
		try {
			if (separator < 0) {
				for (Function member : family) {
					member.setName(name, SourceType.USER_DEFINED);
				}
				List<Map<String, Object>> vtableFields = renameVtableFields(program, family, name);
				commit = true;
				Map<String, Object> result = functionMap(function);
				result.put("propagated", family.size() > 1);
				result.put("virtual_family_size", family.size());
				result.put("renamed_functions", before);
				result.put("vtable_fields", vtableFields);
				return result;
			}
			String namespacePath = name.substring(0, separator);
			String baseName = name.substring(separator + delimiter.length());
			if (baseName.isBlank()) {
				throw new BridgeException("invalid_argument",
					"Function name must be '<namespace>::<name>' with a non-empty base name: " + name);
			}
			Namespace target = resolveNamespaceHierarchy(program, namespacePath);
			if (target == null) {
				throw new BridgeException("invalid_argument",
					"Namespace components must be non-empty: " + name);
			}
			for (Function member : family) {
				member.setName(baseName, SourceType.USER_DEFINED);
				if (member != function) {
					continue;
				}
				if (!member.getParentNamespace().equals(target)) {
					try {
						member.getSymbol().setNamespace(target);
					}
					catch (DuplicateNameException error) {
						throw new BridgeException("already_exists",
							"A symbol named '" + baseName + "' already exists in namespace '"
								+ target.getName(true) + "'", error);
					}
					catch (InvalidInputException | CircularDependencyException error) {
						throw new BridgeException("namespace_failed",
							"Could not move function into namespace '" + target.getName(true)
								+ "': " + error.getMessage(), error);
					}
				}
			}
			List<Map<String, Object>> vtableFields = renameVtableFields(program, family, baseName);
			commit = true;
			Map<String, Object> result = functionMap(function);
			result.put("propagated", family.size() > 1);
			result.put("virtual_family_size", family.size());
			result.put("renamed_functions", before);
			result.put("vtable_fields", vtableFields);
			return result;
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	/** Renames applied vtable slot fields that point at any member of a function family. */
	private static List<Map<String, Object>> renameVtableFields(Program program,
		List<Function> family, String requestedName) {
		String fieldName = vtableFieldName(requestedName);
		Set<String> familyAddresses = new HashSet<>();
		for (Function function : family) {
			familyAddresses.add(function.getEntryPoint().toString());
			if (function.isThunk()) {
				Function target = function.getThunkedFunction(true);
				if (target != null) {
					familyAddresses.add(target.getEntryPoint().toString());
				}
			}
		}
		Set<String> changedSlots = new HashSet<>();
		List<Map<String, Object>> changed = new ArrayList<>();
		for (Map<String, Object> classModel : RttiAnalysisStore.load(program).values()) {
			for (Map<String, Object> vtable : mapList(classModel.get("vtables"))) {
				Address vtableAddress = graphAddress(program, vtable.get("address"));
				if (vtableAddress == null) {
					continue;
				}
				Data data = program.getListing().getDataAt(vtableAddress);
				if (data == null || !(data.getDataType() instanceof Structure structure)) {
					continue;
				}
				for (Map<String, Object> slot : mapList(vtable.get("slots"))) {
					int index = integerValue(slot.get("index"), -1);
					if (index < 0) {
						continue;
					}
					Map<String, Object> function = objectMap(slot.get("function"));
					Map<String, Object> canonical = objectMap(slot.get("canonical_function"));
					Address functionAddress = graphAddress(program,
						function == null ? null : function.get("address"));
					Address canonicalAddress = graphAddress(program,
						canonical == null ? null : canonical.get("address"));
					String functionKey = functionAddress == null ? "" : functionAddress.toString();
					String canonicalKey = canonicalAddress == null ? "" : canonicalAddress.toString();
					if (!familyAddresses.contains(functionKey) && !familyAddresses.contains(canonicalKey)) {
						continue;
					}
					DataTypeComponent component;
					try {
						component = structure.getComponent(index);
					}
					catch (RuntimeException ignored) {
						continue;
					}
					if (component == null) {
						continue;
					}
					String slotKey = structure.getPathName() + ":" + component.getOrdinal();
					if (!changedSlots.add(slotKey) || fieldName.equals(component.getFieldName())) {
						continue;
					}
					String previousName = component.getFieldName();
					try {
						component.setFieldName(fieldName);
					}
					catch (RuntimeException ignored) {
						changedSlots.remove(slotKey);
						continue;
					}
					Map<String, Object> item = new LinkedHashMap<>();
					item.put("structure", structure.getPathName());
					item.put("vtable_address", addressMap(vtableAddress));
					item.put("slot", index);
					item.put("ordinal", component.getOrdinal());
					item.put("offset", component.getOffset());
					item.put("before", previousName);
					item.put("after", fieldName);
					changed.add(item);
				}
			}
		}
		return changed;
	}

	private static String vtableFieldName(String name) {
		int separator = name.lastIndexOf(Namespace.NAMESPACE_DELIMITER);
		return separator < 0 ? name : name.substring(separator + Namespace.NAMESPACE_DELIMITER.length());
	}

	private static List<Map<String, Object>> restoreVtableFields(Program program,
		List<Map<String, Object>> fields) {
		List<Map<String, Object>> changed = new ArrayList<>();
		for (Map<String, Object> field : fields) {
			Object rawPath = field.get("structure");
			int ordinal = integerValue(field.get("ordinal"), -1);
			if (!(rawPath instanceof String path) || ordinal < 0) {
				continue;
			}
			int separator = path.lastIndexOf('/');
			if (separator <= 0 || separator == path.length() - 1) {
				continue;
			}
			DataType dataType = program.getDataTypeManager().getDataType(new DataTypePath(
				path.substring(0, separator), path.substring(separator + 1)));
			if (!(dataType instanceof Structure structure)) {
				continue;
			}
			DataTypeComponent component;
			try {
				component = structure.getComponent(ordinal);
			}
			catch (RuntimeException ignored) {
				continue;
			}
			if (component == null) {
				continue;
			}
			String desired = field.get("name") instanceof String name ? name : null;
			String previousName = component.getFieldName();
			if (java.util.Objects.equals(previousName, desired)) {
				continue;
			}
			try {
				component.setFieldName(desired);
			}
			catch (RuntimeException ignored) {
				continue;
			}
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("structure", path);
			item.put("ordinal", ordinal);
			item.put("offset", component.getOffset());
			item.put("before", previousName);
			item.put("after", desired);
			changed.add(item);
		}
		return changed;
	}

	private static int integerValue(Object value, int defaultValue) {
		return value instanceof Number number ? number.intValue() : defaultValue;
	}

	private static List<Function> virtualFunctionFamily(Program program, Function target) {
		Map<String, Set<String>> graph = new HashMap<>();
		Map<String, Address> addresses = new HashMap<>();
		String targetKey = target.getEntryPoint().toString();
		for (Map<String, Object> classModel : RttiAnalysisStore.load(program).values()) {
			for (Map<String, Object> vtable : mapList(classModel.get("vtables"))) {
				for (Map<String, Object> slot : mapList(vtable.get("slots"))) {
					Map<String, Object> function = objectMap(slot.get("function"));
					Address slotAddress = graphAddress(program, function == null ? null : function.get("address"));
					if (slotAddress == null) {
						continue;
					}
					String slotKey = slotAddress.toString();
					addresses.put(slotKey, slotAddress);
					graph.computeIfAbsent(slotKey, ignored -> new HashSet<>());
					Map<String, Object> canonical = objectMap(slot.get("canonical_function"));
					Address canonicalAddress = graphAddress(program,
						canonical == null ? null : canonical.get("address"));
					if (canonicalAddress != null) {
						String canonicalKey = canonicalAddress.toString();
						addresses.put(canonicalKey, canonicalAddress);
						connect(graph, slotKey, canonicalKey);
					}
					for (String relationKey : List.of("parent_relations", "child_relations")) {
						for (Map<String, Object> relation : mapList(slot.get(relationKey))) {
							Map<String, Object> related = objectMap(relation.get("function"));
							Address relatedAddress = graphAddress(program,
								related == null ? null : related.get("address"));
							if (relatedAddress != null) {
								String relatedKey = relatedAddress.toString();
								addresses.put(relatedKey, relatedAddress);
								connect(graph, slotKey, relatedKey);
							}
						}
					}
				}
			}
		}
		if (!graph.containsKey(targetKey)) {
			return List.of(target);
		}
		Set<String> visited = new HashSet<>();
		Deque<String> pending = new ArrayDeque<>();
		pending.add(targetKey);
		while (!pending.isEmpty()) {
			String current = pending.removeFirst();
			if (!visited.add(current)) {
				continue;
			}
			for (String neighbor : graph.getOrDefault(current, Set.of())) {
				if (!visited.contains(neighbor)) {
					pending.addLast(neighbor);
				}
			}
		}
		List<Function> result = new ArrayList<>();
		result.add(target);
		for (String key : visited) {
			Address address = addresses.get(key);
			Function member = address == null ? null : program.getFunctionManager().getFunctionAt(address);
			if (member != null && member != target && result.stream().noneMatch(existing -> existing.getEntryPoint().equals(address))) {
				result.add(member);
			}
		}
		return result;
	}

	private static void connect(Map<String, Set<String>> graph, String left, String right) {
		graph.computeIfAbsent(left, ignored -> new HashSet<>()).add(right);
		graph.computeIfAbsent(right, ignored -> new HashSet<>()).add(left);
	}

	private static Map<String, Object> objectMap(Object value) {
		return value instanceof Map<?, ?> map ? Json.object(map) : null;
	}

	private static Address graphAddress(Program program, Object value) {
		if (value == null) {
			return null;
		}
		try {
			return addressValue(program, value);
		}
		catch (RuntimeException ignored) {
			return null;
		}
	}

	/** Resolves or creates a "::"-separated namespace path under the global namespace. */
	private Namespace resolveNamespaceHierarchy(Program program, String namespacePath) {
		String delimiter = Namespace.NAMESPACE_DELIMITER;
		Namespace current = program.getGlobalNamespace();
		// Limit -1 keeps trailing empty components, so "A::" is rejected too.
		for (String component : namespacePath.split(java.util.regex.Pattern.quote(delimiter), -1)) {
			if (component.isBlank()) {
				return null;
			}
			Namespace child = program.getSymbolTable().getNamespace(component, current);
			if (child == null) {
				try {
					child = program.getSymbolTable().getOrCreateNameSpace(
						current, component, SourceType.USER_DEFINED);
				}
				catch (InvalidInputException error) {
					throw new BridgeException("namespace_failed",
						"Invalid namespace component '" + component + "': " + error.getMessage(), error);
				}
				catch (Exception error) {
					throw new BridgeException("namespace_failed",
						"Could not create namespace '" + component + "': " + error.getMessage(), error);
				}
			}
			current = child;
		}
		return current;
	}

	private Map<String, Object> setFunctionComment(Program program, Map<String, Object> arguments) {
		Function function = functionAt(program, arguments);
		String comment = Json.string(arguments, "comment");
		int transaction = program.startTransaction("AETHER: set function comment");
		boolean commit = false;
		try {
			function.setComment(comment.isBlank() ? null : comment);
			commit = true;
			return functionMap(function);
		}
		finally {
			program.endTransaction(transaction, commit);
		}
	}

	private Map<String, Object> directAnnotationOperation(Program program, Map<String, Object> arguments, String kind) {
		Map<String, Object> target = new LinkedHashMap<>();
		if ("rename_variable".equals(kind) || "retype_variable".equals(kind)) {
			Object address = arguments.get("address");
			if (address == null) {
				address = arguments.get("location");
			}
			 target.put("function_address", address);
			 target.put("variable_name", arguments.get("variable_name"));
		}
		else {
			Object address = arguments.get("address");
			target.put("address", address == null ? arguments.get("location") : address);
		}
		Map<String, Object> operation = new LinkedHashMap<>();
		operation.put("id", "direct-" + kind);
		operation.put("kind", kind);
		operation.put("target", target);
		Object value = "retype_variable".equals(kind) ? arguments.get("data_type") : arguments.get("name");
		operation.put("value", value == null ? arguments.get("comment") : value);
		if (arguments.get("comment_kind") != null) {
			operation.put("comment_kind", arguments.get("comment_kind"));
		}
		return applyAnnotationBatch(program, Map.of("operations", List.of(operation)));
	}

	private Map<String, Object> directFunctionDefinition(Program program, Map<String, Object> arguments) {
		Map<String, Object> target = new LinkedHashMap<>();
		Object address = arguments.get("address");
		if (address == null) {
			address = arguments.get("location");
		}
		target.put("function_address", address);
		Map<String, Object> definition = new LinkedHashMap<>();
		definition.put("return_type", arguments.get("return_type"));
		definition.put("parameters", arguments.get("parameters"));
		definition.put("varargs", arguments.getOrDefault("varargs", false));
		Map<String, Object> operation = new LinkedHashMap<>();
		operation.put("id", "direct-update_function_definition");
		operation.put("kind", "update_function_definition");
		operation.put("target", target);
		operation.put("value", Json.stringify(definition));
		return applyAnnotationBatch(program, Map.of("operations", List.of(operation)));
	}

	private Function functionAt(Program program, Map<String, Object> arguments) {
		Address address = locationArgument(program, arguments);
		Function function = program.getFunctionManager().getFunctionAt(address);
		if (function == null) {
			function = program.getFunctionManager().getFunctionContaining(address);
		}
		if (function == null) {
			throw new BridgeException("not_found", "No function at address " + address);
		}
		return function;
	}

	private static Map<String, Object> functionMap(Function function) {
		Map<String, Object> result = new LinkedHashMap<>();
		Map<String, Object> reference = functionReference(function);
		result.put("name", reference.get("name"));
		result.put("qualified_name", reference.get("qualified_name"));
		result.put("namespace", reference.get("namespace"));
		result.put("address", reference.get("address"));
		result.put("signature", function.getPrototypeString(false, false));
		result.put("comment", function.getComment() == null ? "" : function.getComment());
		result.put("external", function.isExternal());
		result.put("thunk", function.isThunk());
		result.putAll(functionDefinitionMap(function));
		Symbol symbol = function.getSymbol();
		result.put("default_name", symbol != null && symbol.getSource() == SourceType.DEFAULT);
		return result;
	}

	private static Map<String, Object> functionReference(Function function) {
		Map<String, Object> result = new LinkedHashMap<>();
		Namespace parent = function.getParentNamespace();
		String namespace = parent == null || parent.isGlobal() ? null : parent.getName(true);
		String name = function.getName();
		result.put("address", addressMap(function.getEntryPoint()));
		result.put("name", name);
		result.put("qualified_name", namespace == null || namespace.isBlank() ? name : namespace + "::" + name);
		result.put("namespace", namespace);
		return result;
	}

	private static Map<String, Object> functionDefinitionMap(Function function) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("return_type", function.getReturnType().getDisplayName());
		result.put("return_type_path", function.getReturnType().getPathName());
		result.put("calling_convention", function.getCallingConventionName());
		result.put("varargs", function.hasVarArgs());
		result.put("custom_storage", function.hasCustomVariableStorage());
		List<Map<String, Object>> parameters = new ArrayList<>();
		for (Parameter parameter : function.getParameters()) {
			Map<String, Object> item = new LinkedHashMap<>();
			item.put("name", parameter.getName());
			item.put("data_type", parameter.getDataType().getDisplayName());
			item.put("data_type_path", parameter.getDataType().getPathName());
			item.put("ordinal", parameter.getOrdinal());
			item.put("auto_parameter", parameter.isAutoParameter());
			VariableStorage storage = parameter.getVariableStorage();
			if (storage != null) {
				item.put("storage", storage.toString());
				item.put("storage_serialization", storage.getSerializationString());
			}
			parameters.add(item);
		}
		result.put("parameters", parameters);
		return result;
	}

	private static Address locationArgument(Program program, Map<String, Object> arguments) {
		Object raw = arguments.get("address");
		if (raw == null) {
			raw = arguments.get("location");
		}
		if (!(raw instanceof Map<?, ?>)) {
			throw new BridgeException("invalid_identity", "An address-qualified reference is required");
		}
		Map<String, Object> address = Json.object(raw);
		String offsetValue = Json.string(address, "offset");
		String spaceName = optionalString(address, "space");
		AddressSpace space = spaceName == null
			? program.getAddressFactory().getDefaultAddressSpace()
			: program.getAddressFactory().getAddressSpace(spaceName);
		if (space == null) {
			throw new BridgeException("invalid_argument", "Unknown address space: " + spaceName);
		}
		try {
			long offset = parseOffset(offsetValue);
			return space.getAddress(offset);
		}
		catch (RuntimeException e) {
			throw new BridgeException("invalid_argument", "Invalid address: " + offsetValue, e);
		}
	}

	private static Object requiredArgument(Map<String, Object> arguments, String key) {
		Object value = arguments.get(key);
		if (value == null) {
			throw new BridgeException("invalid_identity", key + " is required");
		}
		return value;
	}

	private static String nameAt(Program program, Address address) {
		Symbol symbol = program.getSymbolTable().getPrimarySymbol(address);
		if (symbol != null) {
			return symbol.getName();
		}
		Function function = program.getFunctionManager().getFunctionContaining(address);
		return function == null ? address.toString() : function.getName();
	}

	private static String segmentName(Program program, Address address) {
		MemoryBlock block = program.getMemory().getBlock(address);
		return block == null ? "unknown" : block.getName();
	}

	private static String instructionText(CodeUnit codeUnit) {
		if (!(codeUnit instanceof Instruction instruction)) {
			return null;
		}
		StringBuilder result = new StringBuilder(instruction.getMnemonicString());
		for (int index = 0; index < instruction.getNumOperands(); index++) {
			String operand = instruction.getDefaultOperandRepresentation(index);
			if (operand != null && !operand.isBlank()) {
				result.append(index == 0 ? " " : ", ").append(operand);
			}
		}
		return result.toString();
	}

	private static String printableString(Program program, Address address, int count) {
		try {
			byte[] bytes = new byte[count];
			int read = program.getMemory().getBytes(address, bytes);
			StringBuilder result = new StringBuilder();
			for (int index = 0; index < read && bytes[index] != 0; index++) {
				int value = bytes[index] & 0xff;
				if (value < 0x20 || value > 0x7e) {
					return result.length() >= 4 ? result.toString() : "No string found";
				}
				result.append((char) value);
			}
			return result.length() >= 4 ? result.toString() : "No string found";
		}
		catch (MemoryAccessException e) {
			return "Error decoding string: " + e.getMessage();
		}
	}

	private static String toHex(byte[] bytes, int length) {
		StringBuilder result = new StringBuilder(length * 2);
		for (int index = 0; index < length; index++) {
			result.append(String.format("%02x", bytes[index] & 0xff));
		}
		return result.toString();
	}

	private static long parseOffset(String value) {
		String normalized = value.trim().toLowerCase();
		if (normalized.startsWith("0x")) {
			normalized = normalized.substring(2);
		}
		if (normalized.isEmpty()) {
			throw new NumberFormatException("empty offset");
		}
		return Long.parseUnsignedLong(normalized, 16);
	}

	public static Map<String, Object> addressMap(Address address) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("space", address.getAddressSpace().getName());
		result.put("offset", Long.toUnsignedString(address.getOffset(), 16));
		return result;
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

	private static String qualifiedFunctionName(Function function) {
		Namespace parent = function.getParentNamespace();
		if (parent == null || parent.isGlobal()) {
			return function.getName();
		}
		String namespace = parent.getName(true);
		return namespace == null || namespace.isBlank() ? function.getName() : namespace + "::" + function.getName();
	}

	private static int integerArgument(Map<String, Object> arguments, String key, int defaultValue) {
		Object value = arguments.get(key);
		if (value == null) {
			return defaultValue;
		}
		if (value instanceof Number number) {
			return number.intValue();
		}
		throw new BridgeException("invalid_argument", key + " must be an integer");
	}

	private static String optionalString(Map<String, Object> arguments, String key) {
		Object value = arguments.get(key);
		if (value == null) {
			return null;
		}
		if (value instanceof String string) {
			return string;
		}
		throw new BridgeException("invalid_argument", key + " must be a string");
	}

	public static final class BridgeException extends RuntimeException {
		private final String code;

		public BridgeException(String code, String message) {
			super(message);
			this.code = code;
		}

		public BridgeException(String code, String message, Throwable cause) {
			super(message, cause);
			this.code = code;
		}

		public String code() {
			return code;
		}
	}
}
