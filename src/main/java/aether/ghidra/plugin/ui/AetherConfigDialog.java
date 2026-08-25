package aether.ghidra.plugin.ui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JTextField;

import docking.DialogComponentProvider;
import ghidra.framework.plugintool.PluginTool;

import aether.ghidra.observability.DebugLog;
import aether.ghidra.plugin.config.AetherConfigStore;
import aether.ghidra.plugin.config.AetherToolConfigStore;

/** Ghidra dialog for the persisted Python agent configuration. */
public final class AetherConfigDialog extends DialogComponentProvider {
	private static final int DEFAULT_MAX_TOKENS = 65_536;

	private final Runnable savedCallback;
	private final Map<String, Object> config;
	private final JTextField apiKey = new JPasswordField();
	private final JTextField model = new JTextField();
	private final JTextField memoryModel = new JTextField();
	private final JTextField baseUrl = new JTextField();
	private final JTextField logFile = new JTextField();
	private final JTextField conversationLogFile = new JTextField();
	private final JTextField maxTokens = new JTextField();
	private final JTextField maxIterations = new JTextField();
	private final JTextField retries = new JTextField();
	private final JTextField retryDelay = new JTextField();
	private final JTextField maxToolCalls = new JTextField();
	private final JTextField maxToolOutput = new JTextField();
	private final JTextField indexingModel = new JTextField();
	private final JTextField indexingBatchSize = new JTextField();
	private final JTextField indexingMaxFunctionSize = new JTextField();
	private final JTextField indexingMaxDecompileSize = new JTextField();
	private final JTextField indexingRetryMax = new JTextField();
	private final JCheckBox indexingCache = new JCheckBox("Cache pseudocode for resumable indexing");
	private final JCheckBox debug = new JCheckBox("Enable debug logging");
	private final Map<String, JCheckBox> toolGroups = new LinkedHashMap<>();

	public AetherConfigDialog(PluginTool tool, Runnable savedCallback) {
		super("AETHER Configuration");
		this.savedCallback = savedCallback;
		this.config = AetherConfigStore.load();
		buildPanel();
		setDefaultSize(620, 800);
		setFocusComponent(model);
		addOKButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		try {
			Map<String, Object> updated = new LinkedHashMap<>(config);
			updated.put("OPENAI_API_KEY", apiKey.getText());
			updated.put("OPENAI_MODEL", model.getText().trim());
			updated.put("OPENAI_MEMORY_MODEL", memoryModel.getText().trim());
			updated.put("OPENAI_BASE_URL", baseUrl.getText().trim());
			updated.put("LOG_FILE", logFile.getText().trim());
			updated.put("CONVERSATION_LOG_FILE", conversationLogFile.getText().trim());
			updated.put("DEBUG", debug.isSelected());
			updated.put("CHATBOT_MAX_TOKENS", positiveInteger(maxTokens, "Maximum tokens", true));
			updated.put("CHATBOT_MAX_ITERATIONS", integer(maxIterations, "Maximum iterations"));
			updated.put("CHATBOT_REQUEST_RETRIES", nonNegativeInteger(retries, "Request retries"));
			updated.put("CHATBOT_REQUEST_RETRY_DELAY_SEC", nonNegativeDecimal(retryDelay, "Retry delay"));
			updated.put("CHATBOT_MAX_TOOL_CALLS", nonNegativeInteger(maxToolCalls, "Maximum tool calls"));
			updated.put("CHATBOT_MAX_CUMULATIVE_TOOL_OUTPUT", nonNegativeInteger(maxToolOutput,
				"Maximum cumulative tool output"));
			updated.put("INDEXING_MODEL", indexingModel.getText().trim());
			updated.put("INDEXING_BATCH_SIZE", positiveInteger(indexingBatchSize, "Index batch size", true));
			updated.put("INDEXING_MAX_FUNC_SIZE_BYTES", nonNegativeInteger(indexingMaxFunctionSize, "Index maximum function size"));
			updated.put("INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES", nonNegativeInteger(indexingMaxDecompileSize, "Index maximum decompile size"));
			updated.put("INDEXING_FAILED_RETRY_MAX", nonNegativeInteger(indexingRetryMax, "Index retry maximum"));
			updated.put("INDEXING_PSEUDOCODE_CACHE_ENABLED", indexingCache.isSelected());
			AetherConfigStore.save(updated);
			Map<String, Boolean> groups = new LinkedHashMap<>();
			toolGroups.forEach((name, checkbox) -> groups.put(name, checkbox.isSelected()));
			AetherToolConfigStore.saveGroups(groups);
			DebugLog.debug(this, "saved agent configuration path=" + AetherConfigStore.path());
			if (savedCallback != null) {
				savedCallback.run();
			}
			close();
		}
		catch (RuntimeException e) {
			setStatusText(e.getMessage());
		}
	}

	private void buildPanel() {
		JPanel panel = new JPanel(new GridBagLayout());
		panel.setBorder(BorderFactory.createEmptyBorder(8, 8, 8, 8));
		int row = 0;
		row = addTextRow(panel, row, "OpenAI API key", apiKey,
			stringValue("OPENAI_API_KEY", "OPENAI_API_KEY"));
		row = addTextRow(panel, row, "Chat model", model,
			stringValue("OPENAI_MODEL", "qwen/qwen3-coder"));
		row = addTextRow(panel, row, "Memory model", memoryModel,
			stringValue("OPENAI_MEMORY_MODEL", ""));
		row = addTextRow(panel, row, "OpenAI-compatible base URL", baseUrl,
			stringValue("OPENAI_BASE_URL", "https://openrouter.ai/api/v1"));
		row = addTextRow(panel, row, "Python log file", logFile,
			stringValue("LOG_FILE", ""));
		row = addTextRow(panel, row, "Conversation log file (JSONL)", conversationLogFile,
			stringValue("CONVERSATION_LOG_FILE", ""));
		debug.setSelected(AetherConfigStore.bool(config, "DEBUG", false));
		GridBagConstraints debugConstraints = constraints(row++, 1);
		debugConstraints.gridwidth = 2;
		panel.add(debug, debugConstraints);

		Map<String, Boolean> configuredGroups = AetherToolConfigStore.loadGroups();
		JPanel groupsPanel = new JPanel(new GridLayout(0, 1));
		groupsPanel.setBorder(BorderFactory.createTitledBorder("Chatbot tool groups"));
		addToolGroup(groupsPanel, configuredGroups, "program_read", "Program inspection (read-only)");
		addToolGroup(groupsPanel, configuredGroups, "analysis_context", "Analysis context");
		addToolGroup(groupsPanel, configuredGroups, "program_write", "Program mutation (renames/comments)");
		addToolGroup(groupsPanel, configuredGroups, "planning", "Planning");
		addToolGroup(groupsPanel, configuredGroups, "memory", "Memory");
		addToolGroup(groupsPanel, configuredGroups, "conversation", "Conversation state");
		addToolGroup(groupsPanel, configuredGroups, "annotation_read", "Annotation context gathering");
		addToolGroup(groupsPanel, configuredGroups, "annotation_write", "Annotation writes and undo");
		GridBagConstraints groupConstraints = constraints(row++, 1);
		groupConstraints.gridwidth = 2;
		groupConstraints.fill = GridBagConstraints.HORIZONTAL;
		groupConstraints.weightx = 1;
		panel.add(groupsPanel, groupConstraints);

		row = addTextRow(panel, row, "Maximum tokens", maxTokens,
			Integer.toString(AetherConfigStore.integer(config, "CHATBOT_MAX_TOKENS", DEFAULT_MAX_TOKENS)));
		row = addTextRow(panel, row, "Maximum iterations (-1 = unlimited)", maxIterations,
			Integer.toString(AetherConfigStore.integer(config, "CHATBOT_MAX_ITERATIONS", -1)));
		row = addTextRow(panel, row, "Request retries", retries,
			Integer.toString(AetherConfigStore.integer(config, "CHATBOT_REQUEST_RETRIES", 2)));
		row = addTextRow(panel, row, "Retry delay (seconds)", retryDelay,
			Double.toString(AetherConfigStore.decimal(config, "CHATBOT_REQUEST_RETRY_DELAY_SEC", 1.0)));
		row = addTextRow(panel, row, "Maximum tool calls (0 = unlimited)", maxToolCalls,
			Integer.toString(AetherConfigStore.integer(config, "CHATBOT_MAX_TOOL_CALLS", 10)));
		row = addTextRow(panel, row, "Maximum tool output (0 = unlimited)", maxToolOutput,
			Integer.toString(AetherConfigStore.integer(config, "CHATBOT_MAX_CUMULATIVE_TOOL_OUTPUT", 0)));

		JPanel indexingPanel = new JPanel(new GridBagLayout());
		indexingPanel.setBorder(BorderFactory.createTitledBorder("Function indexing"));
		int indexingRow = 0;
		indexingRow = addTextRow(indexingPanel, indexingRow, "Indexing model (blank = chat model)", indexingModel,
			AetherConfigStore.string(config, "INDEXING_MODEL", ""));
		indexingRow = addTextRow(indexingPanel, indexingRow, "Batch size", indexingBatchSize,
			Integer.toString(AetherConfigStore.integer(config, "INDEXING_BATCH_SIZE", 50)));
		indexingRow = addTextRow(indexingPanel, indexingRow, "Maximum function size (bytes)", indexingMaxFunctionSize,
			Integer.toString(AetherConfigStore.integer(config, "INDEXING_MAX_FUNC_SIZE_BYTES", 24_576)));
		indexingRow = addTextRow(indexingPanel, indexingRow, "Maximum decompile size (bytes)", indexingMaxDecompileSize,
			Integer.toString(AetherConfigStore.integer(config, "INDEXING_DECOMP_MAX_FUNC_SIZE_BYTES", 12_288)));
		indexingRow = addTextRow(indexingPanel, indexingRow, "Failed-entry retry passes", indexingRetryMax,
			Integer.toString(AetherConfigStore.integer(config, "INDEXING_FAILED_RETRY_MAX", 5)));
		indexingCache.setSelected(AetherConfigStore.bool(config, "INDEXING_PSEUDOCODE_CACHE_ENABLED", true));
		GridBagConstraints cacheConstraints = constraints(indexingRow, 1);
		cacheConstraints.gridwidth = 2;
		indexingPanel.add(indexingCache, cacheConstraints);
		GridBagConstraints indexingConstraints = constraints(row++, 1);
		indexingConstraints.gridwidth = 2;
		indexingConstraints.fill = GridBagConstraints.HORIZONTAL;
		indexingConstraints.weightx = 1;
		panel.add(indexingPanel, indexingConstraints);

		GridBagConstraints filler = constraints(row, 1);
		filler.weighty = 1;
		panel.add(new JPanel(), filler);
		addWorkPanel(panel);
	}

	private void addToolGroup(JPanel panel, Map<String, Boolean> configuredGroups,
		String name, String label) {
		JCheckBox checkbox = new JCheckBox(label, configuredGroups.getOrDefault(name, false));
		toolGroups.put(name, checkbox);
		panel.add(checkbox);
	}

	private String stringValue(String key, String environmentKey) {
		if (config.containsKey(key)) {
			return AetherConfigStore.string(config, key, "");
		}
		String environment = System.getenv(environmentKey);
		return environment == null ? "" : environment;
	}

	private static int addTextRow(JPanel panel, int row, String label, JTextField field, String value) {
		field.setText(value);
		field.setColumns(32);
		GridBagConstraints labelConstraints = constraints(row, 0);
		labelConstraints.anchor = GridBagConstraints.LINE_END;
		panel.add(new JLabel(label + ":"), labelConstraints);
		GridBagConstraints fieldConstraints = constraints(row++, 1);
		fieldConstraints.fill = GridBagConstraints.HORIZONTAL;
		fieldConstraints.weightx = 1;
		panel.add(field, fieldConstraints);
		return row;
	}

	private static GridBagConstraints constraints(int row, int column) {
		GridBagConstraints constraints = new GridBagConstraints();
		constraints.gridx = column;
		constraints.gridy = row;
		constraints.insets = new Insets(3, 4, 3, 4);
		return constraints;
	}

	private static int integer(JTextField field, String name) {
		try {
			return Integer.parseInt(field.getText().trim());
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(name + " must be an integer");
		}
	}

	private static int positiveInteger(JTextField field, String name, boolean strict) {
		int value = integer(field, name);
		if ((strict && value < 1) || (!strict && value < 0)) {
			throw new IllegalArgumentException(name + " must be " + (strict ? "positive" : "non-negative"));
		}
		return value;
	}

	private static int nonNegativeInteger(JTextField field, String name) {
		return positiveInteger(field, name, false);
	}

	private static double nonNegativeDecimal(JTextField field, String name) {
		try {
			double value = Double.parseDouble(field.getText().trim());
			if (value < 0 || Double.isNaN(value) || Double.isInfinite(value)) {
				throw new NumberFormatException();
			}
			return value;
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(name + " must be a non-negative number");
		}
	}
}
