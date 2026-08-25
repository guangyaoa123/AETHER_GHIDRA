package aether.ghidra.plugin.ui;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.Rectangle;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Consumer;

import javax.swing.JComboBox;
import javax.swing.JCheckBox;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.TreeCellRenderer;
import javax.swing.tree.TreePath;

import docking.DialogComponentProvider;
import ghidra.app.context.ProgramLocationActionContext;
import ghidra.framework.plugintool.PluginTool;

import aether.ghidra.program.ProgramRegistry;

/** Unified annotation workflow settings for manual and LLM-guided gathering. */
public final class AnnotationDialog extends DialogComponentProvider {
	private final String programId;
	private final ProgramLocationActionContext location;
	private final Consumer<Map<String, Object>> startCallback;
	private final List<Map<String, Object>> candidates;
	private final List<Map<String, Object>> edges;
	private final JComboBox<String> mode = new JComboBox<>(new String[] { "Manual", "LLM-guided" });
	private final JTextField maxDepth = new JTextField("5");
	private final JTextField maxFunctions = new JTextField("30");
	private final JTextField maxEdges = new JTextField("48");
	private final JTextField instruction = new JTextField("Annotate the selected functions with useful comments and names.");
	private JTree manualSelection;
	private final Set<String> selectedFunctionKeys = new LinkedHashSet<>();
	private final JButton selectDefaultNamed = new JButton("Select all default-named");

	public AnnotationDialog(PluginTool tool, String programId, ProgramLocationActionContext location,
		List<Map<String, Object>> candidates, List<Map<String, Object>> edges,
		Consumer<Map<String, Object>> startCallback) {
		super("AETHER Annotation Workflow");
		this.programId = programId;
		this.location = location;
		this.candidates = candidates == null ? List.of() : candidates;
		this.edges = edges == null ? List.of() : edges;
		this.startCallback = startCallback;
		buildPanel();
		setDefaultSize(680, 470);
		setFocusComponent(instruction);
		addOKButton();
		addCancelButton();
	}

	@Override
	protected void okCallback() {
		try {
			Map<String, Object> request = new LinkedHashMap<>();
			request.put("program_id", programId);
			request.put("address", ProgramRegistry.addressMap(location.getAddress()));
			request.put("mode", mode.getSelectedIndex() == 0 ? "manual" : "llm_guided");
			request.put("max_depth", positiveInteger(maxDepth, "Maximum depth", false));
			request.put("max_functions", positiveInteger(maxFunctions, "Maximum functions", true));
			request.put("max_edges", positiveInteger(maxEdges, "Maximum call edges", true));
			request.put("instruction", instruction.getText().trim());
			if (mode.getSelectedIndex() == 0) {
				List<Map<String, Object>> selected = new ArrayList<>();
				for (Map<String, Object> candidate : candidates) {
					if (selectedFunctionKeys.contains(addressKey(candidate.get("address")))) {
						selected.add(functionReference(candidate));
					}
				}
				if (!selected.isEmpty()) {
					request.put("selected_functions", selected);
				}
			}
			startCallback.accept(request);
			close();
		}
		catch (RuntimeException e) {
			setStatusText(e.getMessage());
		}
	}

	private void buildPanel() {
		JPanel panel = new JPanel(new GridBagLayout());
		int row = 0;
		row = addRow(panel, row, "Gatherer", mode);
		row = addRow(panel, row, "Maximum depth", maxDepth);
		row = addRow(panel, row, "Maximum functions", maxFunctions);
		row = addRow(panel, row, "Maximum call edges", maxEdges);
		row = addRow(panel, row, "Instruction", instruction);
		selectDefaultNamed.setToolTipText("Select every default-named function currently shown in the call graph.");
		row = addRow(panel, row, "Selection preset", selectDefaultNamed);
		GridBagConstraints label = constraints(row, 0);
		label.anchor = GridBagConstraints.NORTHWEST;
		panel.add(new JLabel("Manual function context"), label);
		GridBagConstraints area = constraints(row++, 1);
		area.fill = GridBagConstraints.BOTH;
		area.weightx = 1;
		area.weighty = 1;
		manualSelection = new JTree(buildFunctionTree());
		manualSelection.setRootVisible(true);
		manualSelection.setShowsRootHandles(true);
		manualSelection.setRowHeight(24);
		manualSelection.setCellRenderer(new FunctionTreeRenderer());
		manualSelection.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent event) {
				toggleFunctionAt(event);
			}
		});
		JScrollPane selectionScroll = new JScrollPane(manualSelection);
		selectionScroll.setToolTipText("Click a function row to select it. Use the tree handles to collapse or expand children; the root is always included.");
		panel.add(selectionScroll, area);
		mode.addActionListener(event -> {
			boolean manual = mode.getSelectedIndex() == 0;
			manualSelection.setEnabled(manual);
			selectDefaultNamed.setEnabled(manual);
		});
		selectDefaultNamed.addActionListener(event -> selectDefaultNamedFunctions());
		JPanel wrapper = new JPanel(new BorderLayout());
		wrapper.add(panel, BorderLayout.CENTER);
		addWorkPanel(wrapper);
	}

	private void selectDefaultNamedFunctions() {
		selectedFunctionKeys.clear();
		for (int index = 0; index < candidates.size(); index++) {
			Map<String, Object> candidate = candidates.get(index);
			if (index == 0 || Boolean.TRUE.equals(candidate.get("default_name"))) {
				selectedFunctionKeys.add(addressKey(candidate.get("address")));
			}
		}
		manualSelection.repaint();
	}

	private DefaultMutableTreeNode buildFunctionTree() {
		if (candidates.isEmpty()) {
			return new DefaultMutableTreeNode("No candidate functions");
		}
		Map<String, DefaultMutableTreeNode> nodes = new LinkedHashMap<>();
		Map<String, Integer> depths = new LinkedHashMap<>();
		for (int index = 0; index < candidates.size(); index++) {
			Map<String, Object> candidate = candidates.get(index);
			String key = addressKey(candidate.get("address"));
			nodes.put(key, new DefaultMutableTreeNode(new FunctionNode(candidate, index == 0)));
			depths.put(key, candidate.get("depth") instanceof Number number ? number.intValue() : 0);
		}
		String rootKey = addressKey(candidates.get(0).get("address"));
		selectedFunctionKeys.add(rootKey);
		Map<String, String> parents = new LinkedHashMap<>();
		for (Map<String, Object> edge : edges) {
			String from = addressKey(edge.get("from"));
			String to = addressKey(edge.get("to"));
			if (nodes.containsKey(from) && nodes.containsKey(to) && !from.equals(to) &&
				depths.get(from) < depths.get(to)) {
				parents.putIfAbsent(to, from);
			}
		}
		for (int index = 1; index < candidates.size(); index++) {
			Map<String, Object> candidate = candidates.get(index);
			String key = addressKey(candidate.get("address"));
			String parentKey = parents.get(key);
			if (parentKey == null || !nodes.containsKey(parentKey)) {
				parentKey = nearestParentKey(index, depths.get(key), candidates);
			}
			if (parentKey == null || !nodes.containsKey(parentKey)) {
				parentKey = rootKey;
			}
			nodes.get(parentKey).add(nodes.get(key));
		}
		return nodes.get(rootKey);
	}

	private static String nearestParentKey(int childIndex, int childDepth, List<Map<String, Object>> candidates) {
		for (int index = childIndex - 1; index >= 0; index--) {
			Map<String, Object> candidate = candidates.get(index);
			int depth = candidate.get("depth") instanceof Number number ? number.intValue() : 0;
			if (depth == childDepth - 1) {
				return addressKey(candidate.get("address"));
			}
		}
		return null;
	}

	private void toggleFunctionAt(MouseEvent event) {
		if (!manualSelection.isEnabled() || !SwingUtilities.isLeftMouseButton(event)) {
			return;
		}
		TreePath path = manualSelection.getPathForLocation(event.getX(), event.getY());
		if (path == null) {
			return;
		}
		Rectangle bounds = manualSelection.getPathBounds(path);
		// The checkbox starts at the renderer bounds. Only leave clicks to the
		// left of that area for the tree's expand/collapse handle.
		if (bounds == null || event.getX() < bounds.x) {
			return;
		}
		DefaultMutableTreeNode node = (DefaultMutableTreeNode) path.getLastPathComponent();
		if (!(node.getUserObject() instanceof FunctionNode function) || function.root) {
			return;
		}
		String key = addressKey(function.candidate.get("address"));
		if (!selectedFunctionKeys.add(key)) {
			selectedFunctionKeys.remove(key);
		}
		manualSelection.repaint();
	}

	private static String addressKey(Object value) {
		if (value instanceof Map<?, ?> map) {
			return String.valueOf(map.get("space")) + ":" + String.valueOf(map.get("offset"));
		}
		return String.valueOf(value);
	}

	private static final class FunctionNode {
		private final Map<String, Object> candidate;
		private final boolean root;

		private FunctionNode(Map<String, Object> candidate, boolean root) {
			this.candidate = candidate;
			this.root = root;
		}

		@Override
		public String toString() {
			return (root ? "[root] " : "") + String.valueOf(candidate.get("name")) +
				" @ " + String.valueOf(candidate.get("address"));
		}
	}

	private final class FunctionTreeRenderer extends JPanel implements TreeCellRenderer {
		private final JCheckBox check = new JCheckBox();

		private FunctionTreeRenderer() {
			setOpaque(false);
			check.setOpaque(false);
			setLayout(new BorderLayout());
			add(check, BorderLayout.CENTER);
		}

		@Override
		public Component getTreeCellRendererComponent(JTree tree, Object value, boolean selected,
			boolean expanded, boolean leaf, int row, boolean hasFocus) {
			DefaultMutableTreeNode node = (DefaultMutableTreeNode) value;
			Object userObject = node.getUserObject();
			if (userObject instanceof FunctionNode function) {
				check.setText(function.toString());
				check.setSelected(selectedFunctionKeys.contains(addressKey(function.candidate.get("address"))));
				check.setEnabled(!function.root && tree.isEnabled());
			}
			else {
				check.setText(String.valueOf(userObject));
				check.setSelected(false);
				check.setEnabled(false);
			}
			return this;
		}
	}

	private static Map<String, Object> functionReference(Map<String, Object> candidate) {
		Map<String, Object> result = new LinkedHashMap<>();
		result.put("address", candidate.get("address"));
		result.put("name", candidate.get("name"));
		return result;
	}

	private static int addRow(JPanel panel, int row, String label, java.awt.Component component) {
		GridBagConstraints left = constraints(row, 0);
		left.anchor = GridBagConstraints.LINE_END;
		panel.add(new JLabel(label + ":"), left);
		GridBagConstraints right = constraints(row++, 1);
		right.fill = GridBagConstraints.HORIZONTAL;
		right.weightx = 1;
		panel.add(component, right);
		return row;
	}

	private static GridBagConstraints constraints(int row, int column) {
		GridBagConstraints result = new GridBagConstraints();
		result.gridx = column;
		result.gridy = row;
		result.insets = new Insets(4, 5, 4, 5);
		return result;
	}

	private static int positiveInteger(JTextField field, String name, boolean strict) {
		try {
			int value = Integer.parseInt(field.getText().trim());
			if ((strict && value < 1) || (!strict && value < 0)) {
				throw new NumberFormatException();
			}
			return value;
		}
		catch (NumberFormatException e) {
			throw new IllegalArgumentException(name + " must be a valid " + (strict ? "positive" : "non-negative") + " integer");
		}
	}
}
