package aether.ghidra.plugin;

import java.util.LinkedHashMap;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import javax.swing.SwingUtilities;

import docking.ActionContext;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.MenuData;
import docking.actions.PopupActionProvider;
import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.events.ProgramClosedPluginEvent;
import ghidra.app.events.ProgramOpenedPluginEvent;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import aether.ghidra.AetherPluginPackage;
import aether.ghidra.bridge.BridgeServer;
import aether.ghidra.bridge.Json;
import aether.ghidra.observability.DebugLog;
import aether.ghidra.program.ProgramRegistry;
import aether.ghidra.plugin.config.AetherToolConfigStore;
import aether.ghidra.plugin.ui.AetherConfigDialog;
import aether.ghidra.plugin.ui.AnnotationDialog;
import aether.ghidra.plugin.ui.ChatProvider;
import aether.ghidra.plugin.ui.IndexProvider;

/** Ghidra-side lifecycle and bridge owner for the AETHER integration. */
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = AetherPluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "AETHER Ghidra bridge",
	description = "Exposes explicit, program-scoped Ghidra capabilities to the AETHER Python runtime.",
	eventsConsumed = {
		ProgramOpenedPluginEvent.class,
		ProgramClosedPluginEvent.class,
		ProgramActivatedPluginEvent.class
	}
)
public class AetherPlugin extends Plugin implements PopupActionProvider {
	private static final int DEFAULT_PORT = 8765;

	private ProgramRegistry registry;
	private BridgeServer bridgeServer;
	private AgentClient agentClient;
	private AgentProcess agentProcess;
	private DockingAction analyzeAction;
	private DockingAction chatAction;
	private DockingAction annotationAction;
	private DockingAction cancelAnnotationAction;
	private DockingAction undoAnnotationAction;
	private DockingAction configAction;
	private DockingAction indexAction;
	private volatile String activeAnnotationJobId;
	private ChatProvider chatProvider;
	private IndexProvider indexProvider;

	public AetherPlugin(PluginTool tool) {
		super(tool);
	}

	@Override
	protected void init() {
		super.init();
		DebugLog.configure(tool);
		DebugLog.debug(this, "initializing plugin");
		registry = new ProgramRegistry(tool);
		registry.refreshOpenPrograms();

		int port = readPort();
		DebugLog.debug(this, "configured bridge port=" + port);
		bridgeServer = new BridgeServer(registry, port);
		bridgeServer.start();
		agentClient = new AgentClient();
		chatProvider = new ChatProvider(tool, getName(), new ChatProvider.Backend() {
			@Override
			public Map<String, Object> startChat(String programId, String message, Map<String, Object> address) {
				return agentClient.startChat(programId, message, address);
			}

			@Override
			public Map<String, Object> chatJob(String jobId) {
				return agentClient.chatJob(jobId);
			}

			@Override
			public Map<String, Object> cancelChat(String jobId) {
				return agentClient.cancelChat(jobId);
			}

			@Override
			public Map<String, Object> sessionState(String programId) {
				return agentClient.sessionState(programId);
			}

			@Override
			public void clearSession(String programId) {
				agentClient.clearSession(programId);
			}
		}, tool::setStatusInfo);
		indexProvider = new IndexProvider(tool, getName(), new IndexProvider.Backend() {
			@Override
			public Map<String, Object> startIndex(String programId, boolean resume, boolean reindex) {
				return agentClient.startIndex(programId, resume, reindex);
			}

			@Override
			public Map<String, Object> indexJob(String jobId) {
				return agentClient.indexJob(jobId);
			}

			@Override
			public Map<String, Object> cancelIndex(String jobId) {
				return agentClient.cancelIndex(jobId);
			}

			@Override
			public Map<String, Object> indexStats(String programId) {
				return agentClient.indexStats(programId);
			}

			@Override
			public Map<String, Object> indexEntries(String programId) {
				return agentClient.indexEntries(programId);
			}
		});
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Program currentProgram = programManager == null ? null : programManager.getCurrentProgram();
		String currentProgramId = registry.idFor(currentProgram);
		SwingUtilities.invokeLater(() -> {
			if (chatProvider != null) {
				chatProvider.selectProgram(currentProgramId);
				chatProvider.showDockable();
			}
			if (indexProvider != null) {
				indexProvider.selectProgram(currentProgramId);
				if (!indexProvider.isInTool()) {
					indexProvider.addToTool();
				}
			}
		});
		agentProcess = new AgentProcess(tool);
		try {
			agentProcess.start(bridgeServer.getPort());
		}
		catch (RuntimeException e) {
			Msg.error(this, "Could not start the AETHER Python agent", e);
		}
		DebugLog.debug(this, "plugin initialization complete");
		createAnalyzeAction();
		createChatAction();
		createIndexAction();
		createAnnotationActions();
		createConfigAction();
		tool.addPopupActionProvider(this);

		Msg.info(this, "AETHER Ghidra bridge listening on http://127.0.0.1:" +
			bridgeServer.getPort() + " (authentication disabled; localhost only)");
	}

	@Override
	public void processEvent(ghidra.framework.plugintool.PluginEvent event) {
		if (event instanceof ProgramOpenedPluginEvent opened) {
			DebugLog.debug(this, "program opened");
			registry.register(opened.getProgram());
		}
		else if (event instanceof ProgramClosedPluginEvent closed) {
			DebugLog.debug(this, "program closed");
			String programId = registry.idFor(closed.getProgram());
			if (chatProvider != null && programId != null) {
				chatProvider.programClosed(programId);
			}
			if (indexProvider != null && programId != null) {
				indexProvider.selectProgram(null);
			}
			registry.unregister(closed.getProgram());
		}
		else if (event instanceof ProgramActivatedPluginEvent activated) {
			DebugLog.debug(this, "program activated");
			registry.setActive(activated.getActiveProgram());
			if (chatProvider != null) {
				chatProvider.selectProgram(registry.idFor(activated.getActiveProgram()));
			}
			if (indexProvider != null) {
				indexProvider.selectProgram(registry.idFor(activated.getActiveProgram()));
			}
		}
	}

	@Override
	protected void dispose() {
		DebugLog.debug(this, "disposing plugin");
		tool.removePopupActionProvider(this);
		if (analyzeAction != null) {
			analyzeAction = null;
		}
		if (chatProvider != null) {
			chatProvider.close();
			chatProvider = null;
		}
		if (indexProvider != null) {
			indexProvider.close();
			indexProvider = null;
		}
		chatAction = null;
		indexAction = null;
		annotationAction = null;
		cancelAnnotationAction = null;
		undoAnnotationAction = null;
		if (configAction != null) {
			configAction = null;
		}
		if (agentProcess != null) {
			agentProcess.stop();
			agentProcess = null;
		}
		if (bridgeServer != null) {
			bridgeServer.stop();
			bridgeServer = null;
		}
		if (registry != null) {
			registry.close();
			registry = null;
		}
		super.dispose();
	}

	private void createAnalyzeAction() {
		analyzeAction = new DockingAction("Analyse with AETHER", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return canAnalyze(extractLocationContext(context));
			}

			@Override
			public boolean isValidContext(ActionContext context) {
				return extractLocationContext(context) != null;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				ProgramLocationActionContext locationContext = extractLocationContext(context);
				if (canAnalyze(locationContext)) {
					requestAnalysis(locationContext);
				}
			}
		};
		analyzeAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Analyse selected location" }));
		analyzeAction.setDescription("Ask the Python AETHER agent to analyse this location");
	}

	private void createChatAction() {
		chatAction = new DockingAction("Chat with AETHER", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return canAnalyze(extractLocationContext(context));
			}

			@Override
			public boolean isValidContext(ActionContext context) {
				return extractLocationContext(context) != null;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				ProgramLocationActionContext locationContext = extractLocationContext(context);
				if (!canAnalyze(locationContext) || chatProvider == null) {
					return;
				}
				String programId = registry.idFor(locationContext.getProgram());
				chatProvider.setContext(programId, ProgramRegistry.addressMap(locationContext.getAddress()));
			}
		};
		chatAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Chat with AETHER" }));
		chatAction.setDescription("Open the persistent AETHER chatbot for this location");
	}

	private void createIndexAction() {
		indexAction = new DockingAction("Index / Resume Binary", getName()) {
			@Override
			public boolean isAddToPopup(ActionContext context) {
				return true;
			}

			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return canAnalyze(extractLocationContext(context));
			}

			@Override
			public void actionPerformed(ActionContext context) {
				ProgramLocationActionContext location = extractLocationContext(context);
				if (canAnalyze(location) && indexProvider != null) {
					indexProvider.selectProgram(registry.idFor(location.getProgram()));
					indexProvider.startIndex(false);
				}
			}
		};
		indexAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Index / Resume Binary" }));
		indexAction.setDescription("Create or resume the persistent function index for this Program");
	}

	private void createConfigAction() {
		configAction = new DockingAction("Configure AETHER", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				tool.showDialogOnActiveWindow(new AetherConfigDialog(tool,
					AetherPlugin.this::restartAgentAfterConfiguration));
			}
		};
		configAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Configuration" }));
		configAction.setDescription("Configure the AETHER Python agent");
	}

	private void createAnnotationActions() {
		annotationAction = new DockingAction("Annotate with AETHER", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ProgramLocationActionContext location = extractLocationContext(context);
				if (canAnnotate(location)) {
					if (!AetherToolConfigStore.loadGroups().getOrDefault("annotation_read", false)) {
						Msg.showError(AetherPlugin.this, null, "AETHER Annotation",
							"Enable the Annotation context gathering tool group in AETHER Configuration first.");
						return;
					}
					if (!AetherToolConfigStore.loadGroups().getOrDefault("annotation_write", false)) {
						Msg.showError(AetherPlugin.this, null, "AETHER Annotation",
							"Enable the Annotation writes tool group in AETHER Configuration first.");
						return;
					}
					String programId = registry.idFor(location.getProgram());
					Map<String, Object> address = ProgramRegistry.addressMap(location.getAddress());
					tool.setStatusInfo("AETHER is loading the annotation call tree...");
					CompletableFuture.supplyAsync(() -> agentClient.annotationCandidates(programId, address))
						.thenAccept(tree -> SwingUtilities.invokeLater(() -> {
							tool.setStatusInfo("AETHER annotation call tree loaded");
							@SuppressWarnings("unchecked")
							List<Map<String, Object>> candidates = (List<Map<String, Object>>) tree.getOrDefault("functions", List.of());
							@SuppressWarnings("unchecked")
							List<Map<String, Object>> edges = (List<Map<String, Object>>) tree.getOrDefault("edges", List.of());
							tool.showDialogOnActiveWindow(new AnnotationDialog(tool, programId, location, candidates, edges,
								AetherPlugin.this::startAnnotation));
						}))
						.exceptionally(error -> {
							Throwable cause = error.getCause() == null ? error : error.getCause();
							SwingUtilities.invokeLater(() -> Msg.showError(AetherPlugin.this, null,
								"AETHER Annotation", cause.getMessage()));
							return null;
						});
				}
			}
		};
		annotationAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Annotate with AETHER..." }));
		annotationAction.setDescription("Gather context and annotate the selected function");

		cancelAnnotationAction = new DockingAction("Cancel AETHER annotation", getName()) {
			@Override
			public boolean isEnabledForContext(ActionContext context) {
				return activeAnnotationJobId != null;
			}

			@Override
			public void actionPerformed(ActionContext context) {
				String jobId = activeAnnotationJobId;
				if (jobId != null) {
					CompletableFuture.runAsync(() -> {
						try {
							agentClient.cancelAnnotation(jobId);
							Msg.info(AetherPlugin.this, "AETHER annotation cancellation requested.");
						}
						catch (RuntimeException e) {
							Msg.error(AetherPlugin.this, "Could not cancel AETHER annotation", e);
						}
					});
				}
			}
		};
		cancelAnnotationAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Cancel annotation" }));

		undoAnnotationAction = new DockingAction("Undo last AETHER annotation", getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				ProgramLocationActionContext location = extractLocationContext(context);
				if (canAnnotate(location)) {
					String programId = registry.idFor(location.getProgram());
					CompletableFuture.runAsync(() -> {
						try {
							Map<String, Object> result = agentClient.undoAnnotation(programId);
							SwingUtilities.invokeLater(() -> Msg.showInfo(AetherPlugin.this, null,
								"AETHER Annotation Undo", Json.stringify(result)));
						}
						catch (RuntimeException e) {
							Msg.error(AetherPlugin.this, "Could not undo AETHER annotation", e);
						}
					});
				}
			}
		};
		undoAnnotationAction.setPopupMenuData(new MenuData(new String[] { "AETHER", "Undo last annotation" }));
	}

	private boolean canAnnotate(ProgramLocationActionContext context) {
		return canAnalyze(context);
	}

	private void startAnnotation(Map<String, Object> request) {
		String programId = String.valueOf(request.get("program_id"));
		tool.setStatusInfo("AETHER is gathering annotation context...");
		CompletableFuture.runAsync(() -> {
			try {
				Map<String, Object> job = agentClient.startAnnotation(request);
				String jobId = String.valueOf(job.get("job_id"));
				activeAnnotationJobId = jobId;
				Map<String, Object> status = job;
				while ("queued".equals(status.get("state")) || "running".equals(status.get("state"))) {
					Thread.sleep(500L);
					status = agentClient.annotationJob(jobId);
				}
				Map<String, Object> completed = status;
				SwingUtilities.invokeLater(() -> {
					activeAnnotationJobId = null;
					tool.setStatusInfo("completed".equals(completed.get("state"))
						? "AETHER annotation complete" : "AETHER annotation " + completed.get("state"));
					if ("completed".equals(completed.get("state"))) {
						Msg.showInfo(this, null, "AETHER Annotation", Json.stringify(completed));
					}
					else {
						Msg.showError(this, null, "AETHER Annotation", String.valueOf(completed.get("error")));
					}
				});
			}
			catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				activeAnnotationJobId = null;
			}
			catch (RuntimeException e) {
				activeAnnotationJobId = null;
				Msg.error(this, "AETHER annotation failed for " + programId, e);
			}
		});
	}

	private void restartAgentAfterConfiguration() {
		if (agentProcess == null || !agentProcess.isManaged()) {
			Msg.info(this, "AETHER configuration saved; restart the plugin or managed agent to apply it.");
			return;
		}
		CompletableFuture.runAsync(() -> {
			try {
				agentProcess.restart(bridgeServer.getPort());
				Msg.info(this, "AETHER configuration saved and Python agent restarted.");
			}
			catch (RuntimeException e) {
				Msg.error(this, "AETHER configuration saved, but the Python agent could not be restarted", e);
			}
		});
	}

	@Override
	public List<docking.action.DockingActionIf> getPopupActions(Tool popupTool, ActionContext context) {
		List<docking.action.DockingActionIf> actions = new ArrayList<>();
		if (configAction != null) {
			actions.add(configAction);
		}
		ProgramLocationActionContext locationContext = extractLocationContext(context);
		if (analyzeAction != null && canAnalyze(locationContext)) {
			actions.add(analyzeAction);
		}
		if (chatAction != null && canAnalyze(locationContext)) {
			actions.add(chatAction);
		}
		if (indexAction != null && canAnalyze(locationContext)) {
			actions.add(indexAction);
		}
		if (annotationAction != null && canAnnotate(locationContext)) {
			actions.add(annotationAction);
			if (undoAnnotationAction != null) {
				actions.add(undoAnnotationAction);
			}
		}
		if (cancelAnnotationAction != null && activeAnnotationJobId != null) {
			actions.add(cancelAnnotationAction);
		}
		return actions.isEmpty() ? Collections.emptyList() : actions;
	}

	private boolean canAnalyze(ProgramLocationActionContext context) {
		return context != null && context.getProgram() != null && context.getAddress() != null &&
			registry != null && registry.idFor(context.getProgram()) != null;
	}

	private static ProgramLocationActionContext extractLocationContext(ActionContext context) {
		if (context instanceof ProgramLocationActionContext locationContext) {
			return locationContext;
		}
		if (context != null && context.getContextObject() instanceof ProgramLocationActionContext locationContext) {
			return locationContext;
		}
		if (context != null && context.getSourceObject() instanceof ProgramLocationActionContext locationContext) {
			return locationContext;
		}
		return null;
	}

	private void requestAnalysis(ProgramLocationActionContext context) {
		String programId = registry.idFor(context.getProgram());
		if (programId == null) {
			Msg.showError(this, null, "AETHER Analysis", "The selected program is no longer open.");
			return;
		}

		Map<String, Object> request = new LinkedHashMap<>();
		request.put("program_id", programId);
		request.put("address", ProgramRegistry.addressMap(context.getAddress()));
		request.put("request", "Analyse the selected location and its containing function.");
		request.put("location_type", context.getLocation().getClass().getSimpleName());
		DebugLog.debug(this, "analysis request program_id=" + programId + " address=" + context.getAddress());

		tool.setStatusInfo("AETHER is analysing " + context.getAddress() + "...");
		CompletableFuture
			.supplyAsync(() -> agentClient.analyze(request))
			.thenAccept(result -> SwingUtilities.invokeLater(() -> {
				DebugLog.debug(this, "analysis response program_id=" + programId);
				tool.setStatusInfo("AETHER analysis complete for " + context.getAddress());
				Msg.showInfo(this, null, "AETHER Analysis", Json.stringify(result));
			}))
			.exceptionally(error -> {
				DebugLog.debug(this, "analysis request failed program_id=" + programId);
				Throwable cause = error.getCause() == null ? error : error.getCause();
				SwingUtilities.invokeLater(() -> {
					tool.setStatusInfo("AETHER analysis failed");
					Msg.showError(this, null, "AETHER Analysis", cause.getMessage());
				});
				return null;
			});
	}

	private static int readPort() {
		String configured = System.getenv("AETHER_GHIDRA_PORT");
		if (configured == null || configured.isBlank()) {
			return DEFAULT_PORT;
		}
		try {
			int port = Integer.parseInt(configured);
			if (port < 1 || port > 65535) {
				throw new NumberFormatException("out of range");
			}
			return port;
		}
		catch (NumberFormatException e) {
			Msg.warn(AetherPlugin.class, "Invalid AETHER_GHIDRA_PORT; using " + DEFAULT_PORT);
			return DEFAULT_PORT;
		}
	}
}
