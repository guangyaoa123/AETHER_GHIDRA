package aether.ghidra.plugin.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicLong;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JTable;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JPanel;
import javax.swing.ListSelectionModel;
import javax.swing.RowFilter;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

/** Dockable controls and live status for whole-program function indexing. */
public final class IndexProvider extends ComponentProviderAdapter {
	public interface Backend {
		Map<String, Object> startIndex(String programId, boolean resume, boolean reindex);
		Map<String, Object> indexJob(String jobId);
		Map<String, Object> cancelIndex(String jobId);
		Map<String, Object> indexStats(String programId);
		Map<String, Object> indexEntries(String programId);
	}

	private static final String[] COLUMNS = {
		"Function", "Address", "Importance", "Categories", "Summary",
		"Key Operations", "Constants", "Called Functions", "Callers"
	};
	private final Backend backend;
	private final JPanel root = new JPanel(new BorderLayout(6, 6));
	private final JLabel programLabel = new JLabel("No program selected");
	private final JTextArea status = new JTextArea();
	private final DefaultTableModel tableModel = new DefaultTableModel(COLUMNS, 0) {
		@Override
		public boolean isCellEditable(int row, int column) {
			return false;
		}
	};
	private final JTable table = new JTable(tableModel) {
		@Override
		public String getToolTipText(MouseEvent event) {
			int row = rowAtPoint(event.getPoint());
			int column = columnAtPoint(event.getPoint());
			if (row < 0 || column < 0) {
				return null;
			}
			Object value = getValueAt(row, column);
			return value == null ? null : String.valueOf(value);
		}
	};
	private final TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(tableModel);
	private final JComboBox<String> filterColumn = new JComboBox<>();
	private final JTextField filterText = new JTextField(24);
	private final JButton clearFilter = new JButton("Clear Filter");
	private final JLabel filterCount = new JLabel();
	private final JButton start = new JButton("Index / Resume");
	private final JButton reindex = new JButton("Re-index");
	private final JButton cancel = new JButton("Cancel");
	private final JButton refresh = new JButton("Refresh Index");
	private final JButton stats = new JButton("Refresh Stats");
	private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
		Thread thread = new Thread(r, "aether-index-ui");
		thread.setDaemon(true);
		return thread;
	});
	private volatile String programId;
	private volatile String jobId;
	private final AtomicLong generation = new AtomicLong();

	public IndexProvider(PluginTool tool, String owner, Backend backend) {
		super(tool, "AETHER Indexing", owner);
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		this.backend = backend;
		status.setEditable(false);
		status.setLineWrap(true);
		status.setWrapStyleWord(true);
		status.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
		table.setRowSorter(sorter);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
		table.setFillsViewportHeight(true);
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		configureColumns();
		start.addActionListener(event -> start(false));
		reindex.addActionListener(event -> start(true));
		cancel.addActionListener(event -> cancel());
		refresh.addActionListener(event -> refreshIndex());
		stats.addActionListener(event -> refreshStats());
		filterColumn.addActionListener(event -> applyFilter());
		filterText.getDocument().addDocumentListener(new DocumentListener() {
			@Override
			public void insertUpdate(DocumentEvent event) {
				applyFilter();
			}

			@Override
			public void removeUpdate(DocumentEvent event) {
				applyFilter();
			}

			@Override
			public void changedUpdate(DocumentEvent event) {
				applyFilter();
			}
		});
		clearFilter.addActionListener(event -> filterText.setText(""));
		cancel.setEnabled(false);
		for (String column : COLUMNS) {
			filterColumn.addItem(column);
		}
		filterColumn.insertItemAt("All columns", 0);
		filterColumn.setSelectedIndex(0);
		buildUi();
	}

	@Override
	public javax.swing.JComponent getComponent() {
		return root;
	}

	public void selectProgram(String nextProgramId) {
		generation.incrementAndGet();
		programId = nextProgramId;
		programLabel.setText(nextProgramId == null ? "No program selected" : "Program: " + nextProgramId);
		tableModel.setRowCount(0);
		filterText.setText("");
		status.setText(nextProgramId == null ? "No program selected" : "Loading function index...");
		if (nextProgramId != null) {
			refreshIndex();
		}
	}

	public void showDockable() {
		if (!isInTool()) {
			addToTool();
		}
		setVisible(true);
		toFront();
	}

	public void startIndex(boolean forceReindex) {
		showDockable();
		start(forceReindex);
	}

	public void close() {
		generation.incrementAndGet();
		cancel();
		executor.shutdownNow();
		if (isInTool()) {
			removeFromTool();
		}
	}

	private void buildUi() {
		JPanel header = new JPanel(new BorderLayout(6, 0));
		header.add(new JLabel("AETHER Function Index"), BorderLayout.WEST);
		header.add(programLabel, BorderLayout.CENTER);
		JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
		filterPanel.add(new JLabel("Filter:"));
		filterPanel.add(filterColumn);
		filterPanel.add(filterText);
		filterPanel.add(clearFilter);
		filterPanel.add(filterCount);
		JPanel top = new JPanel();
		top.setLayout(new BoxLayout(top, BoxLayout.Y_AXIS));
		top.add(header);
		top.add(filterPanel);
		JScrollPane statusScroll = new JScrollPane(status);
		statusScroll.setPreferredSize(new Dimension(960, 76));
		top.add(statusScroll);
		root.add(top, BorderLayout.NORTH);
		JScrollPane tableScroll = new JScrollPane(table);
		tableScroll.setPreferredSize(new Dimension(960, 360));
		root.add(tableScroll, BorderLayout.CENTER);
		JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
		buttons.add(refresh);
		buttons.add(stats);
		buttons.add(cancel);
		buttons.add(reindex);
		buttons.add(start);
		root.add(buttons, BorderLayout.SOUTH);
	}

	private void start(boolean forceReindex) {
		String requestedProgram = programId;
		if (requestedProgram == null || jobId != null) {
			return;
		}
		setBusy(true);
		executor.submit(() -> {
			try {
				Map<String, Object> started = backend.startIndex(requestedProgram, !forceReindex, forceReindex);
				String requestedJob = String.valueOf(started.get("job_id"));
				jobId = requestedJob;
				Map<String, Object> current = started;
				while ("queued".equals(current.get("state")) || "running".equals(current.get("state"))) {
					Map<String, Object> snapshot = current;
					SwingUtilities.invokeLater(() -> render(snapshot));
					Thread.sleep(500L);
					current = backend.indexJob(requestedJob);
				}
				Map<String, Object> completed = current;
				SwingUtilities.invokeLater(() -> render(completed));
			}
			catch (InterruptedException error) {
				Thread.currentThread().interrupt();
			}
			catch (RuntimeException error) {
				SwingUtilities.invokeLater(() -> status.setText("Indexing error:\n" + error.getMessage()));
			}
			finally {
				SwingUtilities.invokeLater(() -> {
					jobId = null;
					setBusy(false);
				});
			}
		});
	}

	private void cancel() {
		String requestedJob = jobId;
		if (requestedJob == null) {
			return;
		}
		executor.submit(() -> backend.cancelIndex(requestedJob));
	}

	private void refreshStats() {
		String requestedProgram = programId;
		if (requestedProgram == null) {
			return;
		}
		executor.submit(() -> {
			try {
				Map<String, Object> result = backend.indexStats(requestedProgram);
				SwingUtilities.invokeLater(() -> status.setText(format(result)));
			}
			catch (RuntimeException error) {
				SwingUtilities.invokeLater(() -> status.setText("Stats error:\n" + error.getMessage()));
			}
		});
	}

	private void refreshIndex() {
		String requestedProgram = programId;
		long requestedGeneration = generation.get();
		if (requestedProgram == null) {
			return;
		}
		executor.submit(() -> {
			try {
				Map<String, Object> result = backend.indexEntries(requestedProgram);
				SwingUtilities.invokeLater(() -> {
					if (generation.get() == requestedGeneration && requestedProgram.equals(programId)) {
						renderEntries(result);
					}
				});
			}
			catch (RuntimeException error) {
				SwingUtilities.invokeLater(() -> status.setText("Index error:\n" + error.getMessage()));
			}
		});
	}

	private void render(Map<String, Object> snapshot) {
		Object progress = snapshot.get("progress");
		String progressText = progress instanceof Map<?, ?> values ? format(values) : "";
		status.setText("State: " + snapshot.get("state") + "\n" + progressText);
		if ("completed".equals(snapshot.get("state"))) {
			refreshIndex();
		}
	}

	private void renderEntries(Map<String, Object> result) {
		tableModel.setRowCount(0);
		Object functions = result.get("functions");
		if (functions instanceof List<?> list) {
			for (Object value : list) {
				if (!(value instanceof Map<?, ?> function)) {
					continue;
				}
				List<String> tags = strings(function.get("tags"));
				tableModel.addRow(new Object[] {
					text(function.get("name")),
					text(function.get("address")),
					importance(tags),
					categories(tags),
					text(function.get("summary")),
					join(function.get("key_operations")),
					join(function.get("key_constants")),
					join(function.get("called_functions")),
					join(function.get("caller_functions"))
				});
			}
		}
		status.setText("State: " + result.getOrDefault("state", "PENDING") +
			" | Indexed: " + result.getOrDefault("indexed", tableModel.getRowCount()) +
			" | Rows shown: " + tableModel.getRowCount());
		applyFilter();
	}

	private void applyFilter() {
		String query = filterText.getText().trim();
		int selectedColumn = filterColumn.getSelectedIndex() - 1;
		if (query.isEmpty()) {
			sorter.setRowFilter(null);
		}
		else if (selectedColumn < 0) {
			sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(query)));
		}
		else {
			sorter.setRowFilter(RowFilter.regexFilter("(?i)" + Pattern.quote(query), selectedColumn));
		}
		filterCount.setText(table.getRowCount() + " / " + tableModel.getRowCount() + " rows");
	}

	private void configureColumns() {
		int[] widths = {180, 105, 80, 190, 430, 260, 180, 180, 220};
		for (int index = 0; index < widths.length; index++) {
			table.getColumnModel().getColumn(index).setPreferredWidth(widths[index]);
		}
	}

	private static String text(Object value) {
		return value == null ? "" : String.valueOf(value);
	}

	private static String join(Object value) {
		return String.join(", ", strings(value));
	}

	private static List<String> strings(Object value) {
		if (value instanceof List<?> list) {
			return list.stream().map(IndexProvider::text).filter(item -> !item.isBlank()).toList();
		}
		return value == null ? List.of() : List.of(text(value));
	}

	private static String importance(List<String> tags) {
		return tags.stream().filter(tag -> tag.equals("CRITICAL") || tag.equals("HIGH") ||
			tag.equals("MEDIUM") || tag.equals("LOW") || tag.equals("MINIMAL")).findFirst().orElse("");
	}

	private static String categories(List<String> tags) {
		return String.join(", ", tags.stream().filter(tag -> !tag.equals("CRITICAL") && !tag.equals("HIGH") &&
			!tag.equals("MEDIUM") && !tag.equals("LOW") && !tag.equals("MINIMAL")).toList());
	}

	private static String format(Map<?, ?> values) {
		StringBuilder result = new StringBuilder();
		values.forEach((key, value) -> result.append(key).append(": ").append(value).append('\n'));
		return result.toString();
	}

	private void setBusy(boolean busy) {
		start.setEnabled(!busy);
		reindex.setEnabled(!busy);
		cancel.setEnabled(busy);
		refresh.setEnabled(!busy);
		stats.setEnabled(!busy);
	}
}
