package aether.ghidra.plugin.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTree;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.table.DefaultTableModel;
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;
import javax.swing.tree.TreePath;

import docking.WindowPosition;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;

import aether.ghidra.bridge.Json;

/** Dockable view of structures, recovered classes, inheritance, and virtual dispatch. */
public final class ClassInfoProvider extends ComponentProviderAdapter {
	public interface Backend {
		Map<String, Object> listStructures(String programId);
		Map<String, Object> getStructure(String programId, String path);
		void navigateToAddress(String programId, Map<String, Object> address);
		void selectDataType(String programId, String path);
		void editDataType(String programId, String path);
	}

	private static final String[] GROUP_COLUMNS = {"Role", "Name", "Structure", "Address", "Size"};
	private static final String[] FIELD_COLUMNS = {"Offset", "Name", "Type", "Length", "Comment"};
	private static final String[] FUNCTION_COLUMNS = {"Function", "Address", "Signature"};
	private static final String[] VTABLE_COLUMNS = {"Vtable", "Slot", "Function", "Relation", "Parent Class", "Parent Function"};

	private final Backend backend;
	private final JPanel root = new JPanel(new BorderLayout(6, 6));
	private final JLabel programLabel = new JLabel("No program selected");
	private final JLabel status = new JLabel();
	private final JTextField filter = new JTextField(24);
	private final JButton refresh = new JButton("Refresh Classes");
	private final JPopupMenu typeMenu = new JPopupMenu();
	private final JMenuItem openType = new JMenuItem("Open in Data Type Manager");
	private final JMenuItem editType = new JMenuItem("Edit Type");
	private final DefaultMutableTreeNode classRoot = new DefaultMutableTreeNode("Analyzed Classes");
	private final DefaultTreeModel classTreeModel = new DefaultTreeModel(classRoot);
	private final JTree classes = new JTree(classTreeModel);
	private final DefaultTableModel groupModel = model(GROUP_COLUMNS);
	private final JTable groupStructs = new JTable(groupModel);
	private final JTextArea overview = new JTextArea();
	private final DefaultTableModel fieldModel = model(FIELD_COLUMNS);
	private final JTable fields = new JTable(fieldModel);
	private final DefaultTableModel functionModel = model(FUNCTION_COLUMNS);
	private final JTable functions = new JTable(functionModel);
	private final DefaultTableModel vtableModel = model(VTABLE_COLUMNS);
	private final JTable vtables = new JTable(vtableModel);
	private final JTabbedPane details = new JTabbedPane();
	private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
		Thread thread = new Thread(r, "aether-class-ui");
		thread.setDaemon(true);
		return thread;
	});
	private final AtomicLong generation = new AtomicLong();
	private final AtomicLong refreshSequence = new AtomicLong();
	private final Object refreshLock = new Object();
	private volatile String programId;
	private String selectedTypePath;
	private List<Map<String, Object>> classItems = List.of();
	private List<Map<String, Object>> selectedGroupStructures = List.of();
	private List<Map<String, Object>> selectedFunctionAddresses = List.of();
	private List<Map<String, Object>> selectedVtableAddresses = List.of();
	private ScheduledFuture<?> pendingRefresh;
	private boolean suppressSelectionLoad;

	public ClassInfoProvider(PluginTool tool, String owner, Backend backend) {
		super(tool, "AETHER Classes", owner);
		setDefaultWindowPosition(WindowPosition.RIGHT);
		this.backend = backend;
		classes.setRootVisible(false);
		classes.setShowsRootHandles(true);
		classes.addTreeSelectionListener(event -> loadSelected());
		groupStructs.getSelectionModel().addListSelectionListener(event -> {
			if (!event.getValueIsAdjusting()) {
				navigateGroupRow();
			}
		});
		vtables.getSelectionModel().addListSelectionListener(event -> {
			if (!event.getValueIsAdjusting()) {
				navigateVtableRow();
			}
		});
		functions.getSelectionModel().addListSelectionListener(event -> {
			if (!event.getValueIsAdjusting()) {
				navigateFunctionRow();
			}
		});
		filter.getDocument().addDocumentListener(new DocumentListener() {
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
		refresh.addActionListener(event -> refresh());
		openType.addActionListener(event -> openSelectedType());
		editType.addActionListener(event -> editSelectedType());
		typeMenu.add(openType);
		typeMenu.add(editType);
		classes.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent event) {
				showTypeMenu(event);
			}

			@Override
			public void mouseReleased(MouseEvent event) {
				showTypeMenu(event);
			}
		});
		groupStructs.addMouseListener(new MouseAdapter() {
			@Override
			public void mousePressed(MouseEvent event) {
				showTypeMenu(event);
			}

			@Override
			public void mouseReleased(MouseEvent event) {
				showTypeMenu(event);
			}
		});
		configureTable(groupStructs);
		configureTable(fields);
		configureTable(functions);
		configureTable(vtables);
		overview.setEditable(false);
		overview.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		overview.setLineWrap(true);
		overview.setWrapStyleWord(true);
		buildUi();
	}

	@Override
	public javax.swing.JComponent getComponent() {
		return root;
	}

	public void selectProgram(String nextProgramId) {
		programId = nextProgramId;
		generation.incrementAndGet();
		cancelPendingRefresh();
		classItems = List.of();
		selectedGroupStructures = List.of();
		selectedFunctionAddresses = List.of();
		selectedVtableAddresses = List.of();
		selectedTypePath = null;
		classRoot.removeAllChildren();
		classTreeModel.reload();
		clearDetails();
		programLabel.setText(nextProgramId == null ? "No program selected" : "Program: " + nextProgramId);
		status.setText(nextProgramId == null ? "No program selected" : "Loading analyzed classes...");
		if (nextProgramId != null) {
			refresh();
		}
	}

	public void showDockable() {
		if (!isInTool()) {
			addToTool();
		}
		setVisible(true);
		toFront();
	}

	public void close() {
		generation.incrementAndGet();
		cancelPendingRefresh();
		executor.shutdownNow();
		if (isInTool()) {
			removeFromTool();
		}
	}

	private void buildUi() {
		JPanel header = new JPanel(new BorderLayout(6, 0));
		header.add(new JLabel("AETHER Class Information"), BorderLayout.WEST);
		header.add(programLabel, BorderLayout.CENTER);
		header.add(refresh, BorderLayout.EAST);

		JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 4, 0));
		filterPanel.add(new JLabel("Filter:"));
		filterPanel.add(filter);
		filterPanel.add(status);

		JPanel top = new JPanel(new BorderLayout(0, 4));
		top.add(header, BorderLayout.NORTH);
		top.add(filterPanel, BorderLayout.SOUTH);
		root.add(top, BorderLayout.NORTH);

		JScrollPane classScroll = new JScrollPane(classes);
		classScroll.setPreferredSize(new Dimension(760, 220));
		details.addTab("Overview", new JScrollPane(overview));
		details.addTab("Group Structs", new JScrollPane(groupStructs));
		details.addTab("Fields", new JScrollPane(fields));
		details.addTab("Functions", new JScrollPane(functions));
		details.addTab("Vtables", new JScrollPane(vtables));
		JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT, classScroll, details);
		split.setResizeWeight(0.35);
		root.add(split, BorderLayout.CENTER);
	}

	private void refresh() {
		queryClasses(false);
	}

	public void programChanged(String changedProgramId) {
		if (changedProgramId == null || !changedProgramId.equals(programId)) {
			return;
		}
		synchronized (refreshLock) {
			if (pendingRefresh != null) {
				pendingRefresh.cancel(false);
			}
			pendingRefresh = executor.schedule(() -> {
				synchronized (refreshLock) {
					pendingRefresh = null;
				}
				queryClasses(true);
			}, 350, TimeUnit.MILLISECONDS);
		}
	}

	private void queryClasses(boolean preserveState) {
		String requestedProgram = programId;
		long requestedGeneration = generation.get();
		if (requestedProgram == null) {
			return;
		}
		long requestedSequence = refreshSequence.incrementAndGet();
		executor.submit(() -> {
			try {
				Map<String, Object> result = backend.listStructures(requestedProgram);
				SwingUtilities.invokeLater(() -> {
					if (isCurrent(requestedProgram, requestedGeneration) &&
						requestedSequence == refreshSequence.get()) {
						renderClasses(result, preserveState);
					}
				});
			}
			catch (RuntimeException error) {
				SwingUtilities.invokeLater(() -> {
					if (isCurrent(requestedProgram, requestedGeneration)) {
						status.setText("Class query error: " + error.getMessage());
					}
				});
			}
		});
	}

	private void loadSelected() {
		if (suppressSelectionLoad) {
			return;
		}
		TreePath selection = classes.getSelectionPath();
		if (selection == null || programId == null) {
			return;
		}
		Object value = ((DefaultMutableTreeNode) selection.getLastPathComponent()).getUserObject();
		if (!(value instanceof ClassGroup group)) {
			if (value instanceof GroupStruct member) {
				selectedTypePath = member.path();
				navigateToAddress(member.address());
				loadStructure(member.parentPath(), member.parentName());
			}
			return;
		}
		selectedTypePath = group.path();
		loadStructure(group.path(), group.name());
	}

	private void showTypeMenu(MouseEvent event) {
		if (!event.isPopupTrigger()) {
			return;
		}
		if (event.getSource() == classes) {
			TreePath treePath = classes.getPathForLocation(event.getX(), event.getY());
			if (treePath == null) {
				return;
			}
			classes.setSelectionPath(treePath);
			Object value = ((DefaultMutableTreeNode) treePath.getLastPathComponent()).getUserObject();
			selectedTypePath = value instanceof ClassGroup group ? group.path() :
				value instanceof GroupStruct member ? member.path() : null;
		}
		else if (event.getSource() == groupStructs) {
			int row = groupStructs.rowAtPoint(event.getPoint());
			if (row < 0 || row >= selectedGroupStructures.size()) {
				return;
			}
			groupStructs.setRowSelectionInterval(row, row);
			Object path = selectedGroupStructures.get(row).get("path");
			selectedTypePath = path == null ? null : String.valueOf(path);
		}
		else {
			return;
		}
		if (selectedTypePath == null) {
			return;
		}
		openType.setEnabled(true);
		editType.setEnabled(true);
		typeMenu.show(event.getComponent(), event.getX(), event.getY());
	}

	private void openSelectedType() {
		if (selectedTypePath == null || programId == null) {
			return;
		}
		try {
			backend.selectDataType(programId, selectedTypePath);
			status.setText("Opened " + selectedTypePath + " in Data Type Manager");
		}
		catch (RuntimeException error) {
			status.setText("Data Type Manager error: " + error.getMessage());
		}
	}

	private void editSelectedType() {
		if (selectedTypePath == null || programId == null) {
			return;
		}
		try {
			backend.editDataType(programId, selectedTypePath);
			status.setText("Editing " + selectedTypePath + " in Data Type Manager");
		}
		catch (RuntimeException error) {
			status.setText("Data Type Manager error: " + error.getMessage());
		}
	}

	private void loadStructure(String path, String label) {
		String requestedProgram = programId;
		long requestedGeneration = generation.get();
		status.setText("Loading " + label + "...");
		executor.submit(() -> {
			try {
				Map<String, Object> result = backend.getStructure(requestedProgram, path);
				SwingUtilities.invokeLater(() -> {
					if (isCurrent(requestedProgram, requestedGeneration)) {
						renderDetails(result);
					}
				});
			}
			catch (RuntimeException error) {
				SwingUtilities.invokeLater(() -> status.setText("Class query error: " + error.getMessage()));
			}
		});
	}

	private void renderClasses(Map<String, Object> result, boolean preserveState) {
		String selectedPath = preserveState ? selectedClassPath() : null;
		Set<String> expandedPaths = preserveState ? expandedClassPaths() : null;
		int selectedTab = details.getSelectedIndex();
		classItems = mapList(result.get("structures"));
		rebuildClassTree(expandedPaths);
		status.setText(classItems.size() + " analyzed class(es)");
		details.setSelectedIndex(Math.min(Math.max(0, selectedTab), details.getTabCount() - 1));
		if (selectedPath != null && selectClassPath(selectedPath)) {
			selectedTypePath = selectedPath;
			loadStructure(selectedPath, selectedClassName(selectedPath));
		}
		else if (classRoot.getChildCount() > 0) {
			classes.setSelectionRow(0);
		}
		else {
			clearDetails();
		}
	}

	private void rebuildClassTree(Set<String> expandedPaths) {
		classRoot.removeAllChildren();
		String text = filter.getText().trim().toLowerCase();
		List<ClassGroup> groups = new ArrayList<>();
		Map<String, ClassGroup> byId = new HashMap<>();
		Map<String, ClassGroup> byName = new HashMap<>();
		for (Map<String, Object> item : classItems) {
			ClassGroup group = new ClassGroup(item);
			if (!text.isEmpty() && !group.matches(text)) {
				continue;
			}
			groups.add(group);
			byId.put(group.id(), group);
			byName.putIfAbsent(group.name(), group);
		}
		groups.sort(Comparator.comparing(ClassGroup::name).thenComparing(ClassGroup::path));
		Map<ClassGroup, List<ClassGroup>> children = new LinkedHashMap<>();
		Set<ClassGroup> derived = new HashSet<>();
		for (ClassGroup group : groups) {
			for (Map<String, Object> base : group.bases()) {
				ClassGroup parent = byId.get(baseIdentity(base));
				if (parent == null) {
					parent = byName.get(baseName(base));
				}
				if (parent != null && parent != group) {
					children.computeIfAbsent(parent, ignored -> new ArrayList<>()).add(group);
					derived.add(group);
				}
			}
		}
		for (List<ClassGroup> groupChildren : children.values()) {
			groupChildren.sort(Comparator.comparing(ClassGroup::name).thenComparing(ClassGroup::path));
		}
		for (ClassGroup group : groups) {
			if (!derived.contains(group)) {
				classRoot.add(classNode(group, children, new HashSet<>()));
			}
		}
		if (classRoot.getChildCount() == 0) {
			for (ClassGroup group : groups) {
				classRoot.add(classNode(group, children, new HashSet<>()));
			}
		}
		classTreeModel.reload();
		for (int index = 0; index < classRoot.getChildCount(); index++) {
			expandClassNodes((DefaultMutableTreeNode) classRoot.getChildAt(index), expandedPaths);
		}
	}

	private DefaultMutableTreeNode classNode(ClassGroup group,
		Map<ClassGroup, List<ClassGroup>> children, Set<String> ancestry) {
		DefaultMutableTreeNode node = new DefaultMutableTreeNode(group);
		for (Map<String, Object> member : group.members()) {
			node.add(new DefaultMutableTreeNode(new GroupStruct(member, group)));
		}
		if (!ancestry.add(group.path())) {
			return node;
		}
		for (ClassGroup child : children.getOrDefault(group, List.of())) {
			node.add(classNode(child, children, new HashSet<>(ancestry)));
		}
		return node;
	}

	private void expandClassNodes(DefaultMutableTreeNode node, Set<String> expandedPaths) {
		Object value = node.getUserObject();
		if (value instanceof ClassGroup group &&
			(expandedPaths == null || expandedPaths.contains(group.path()))) {
			classes.expandPath(new TreePath(node.getPath()));
		}
		for (int index = 0; index < node.getChildCount(); index++) {
			expandClassNodes((DefaultMutableTreeNode) node.getChildAt(index), expandedPaths);
		}
	}

	private String selectedClassPath() {
		TreePath selection = classes.getSelectionPath();
		if (selection == null) {
			return null;
		}
		Object[] components = selection.getPath();
		for (int index = components.length - 1; index >= 0; index--) {
			Object value = ((DefaultMutableTreeNode) components[index]).getUserObject();
			if (value instanceof ClassGroup group) {
				return group.path();
			}
		}
		return null;
	}

	private Set<String> expandedClassPaths() {
		Set<String> result = new HashSet<>();
		for (int index = 0; index < classRoot.getChildCount(); index++) {
			collectExpandedClassPaths((DefaultMutableTreeNode) classRoot.getChildAt(index), result);
		}
		return result;
	}

	private void collectExpandedClassPaths(DefaultMutableTreeNode node, Set<String> result) {
		if (node.getUserObject() instanceof ClassGroup group && classes.isExpanded(new TreePath(node.getPath()))) {
			result.add(group.path());
		}
		for (int index = 0; index < node.getChildCount(); index++) {
			collectExpandedClassPaths((DefaultMutableTreeNode) node.getChildAt(index), result);
		}
	}

	private boolean selectClassPath(String path) {
		DefaultMutableTreeNode node = findClassNode(classRoot, path);
		if (node != null) {
			TreePath treePath = new TreePath(node.getPath());
			classes.expandPath(treePath);
			suppressSelectionLoad = true;
			try {
				classes.setSelectionPath(treePath);
			}
			finally {
				suppressSelectionLoad = false;
			}
			return true;
		}
		return false;
	}

	private DefaultMutableTreeNode findClassNode(DefaultMutableTreeNode node, String path) {
		if (node.getUserObject() instanceof ClassGroup group && path.equals(group.path())) {
			return node;
		}
		for (int index = 0; index < node.getChildCount(); index++) {
			DefaultMutableTreeNode found = findClassNode((DefaultMutableTreeNode) node.getChildAt(index), path);
			if (found != null) {
				return found;
			}
		}
		return null;
	}

	private String selectedClassName(String path) {
		for (Map<String, Object> item : classItems) {
			if (path.equals(String.valueOf(item.get("path")))) {
				return String.valueOf(item.getOrDefault("class_name", item.get("name")));
			}
		}
		return path;
	}

	private void renderDetails(Map<String, Object> result) {
		@SuppressWarnings("unchecked")
		Map<String, Object> classInfo = result.get("class") instanceof Map<?, ?> map
			? Json.object(map) : Map.of();
		StringBuilder text = new StringBuilder();
		text.append("Structure: ").append(result.get("path")).append('\n');
		text.append("Size: ").append(result.get("size")).append(" bytes\n");
		text.append("Class: ").append(classInfo.getOrDefault("name", result.get("class_name"))).append('\n');
		text.append("Namespace: ").append(classInfo.getOrDefault("namespace", "")).append('\n');
		text.append("RTTI source: ").append(classInfo.getOrDefault("analysis_source", "not recorded")).append('\n');
		text.append("\nDirect bases:\n");
		for (Map<String, Object> base : mapList(classInfo.get("bases"))) {
			text.append("  ").append(base.get("name"));
			if (base.containsKey("offset")) {
				text.append(" @ 0x").append(Integer.toHexString(number(base.get("offset")).intValue()));
			}
			if (Boolean.TRUE.equals(base.get("virtual"))) {
				text.append(" (virtual)");
			}
			text.append('\n');
		}
		text.append("Inheritance chain: ").append(classInfo.getOrDefault("inheritance_chain", List.of())).append('\n');
		text.append("Derived classes: ").append(classInfo.getOrDefault("derived_classes", List.of())).append('\n');
		overview.setText(text.toString());
		renderGroupStructures(classInfo.get("group_structures"));
		renderFields(result.get("fields"));
		renderFunctions(classInfo.get("non_virtual_functions"));
		renderVtables(classInfo.get("vtables"));
		status.setText("Loaded " + result.get("class_name"));
	}

	private void renderGroupStructures(Object rawStructures) {
		selectedGroupStructures = mapList(rawStructures);
		groupModel.setRowCount(0);
		for (Map<String, Object> member : selectedGroupStructures) {
			groupModel.addRow(new Object[] {member.get("role"), member.get("name"), member.get("path"),
				formatAddress(member.get("address")), member.get("size")});
		}
	}

	private void navigateGroupRow() {
		int row = groupStructs.getSelectedRow();
		if (row < 0 || row >= selectedGroupStructures.size()) {
			return;
		}
		Object path = selectedGroupStructures.get(row).get("path");
		selectedTypePath = path == null ? null : String.valueOf(path);
		navigateToAddress(selectedGroupStructures.get(row).get("address"));
	}

	private void navigateToAddress(Object rawAddress) {
		if (!(rawAddress instanceof Map<?, ?> map) || programId == null) {
			return;
		}
		try {
			backend.navigateToAddress(programId, Json.object(map));
		}
		catch (RuntimeException error) {
			status.setText("Navigation error: " + error.getMessage());
		}
	}

	private void renderFields(Object rawFields) {
		fieldModel.setRowCount(0);
		for (Map<String, Object> field : mapList(rawFields)) {
			fieldModel.addRow(new Object[] {formatOffset(field.get("offset")), field.get("name"),
				field.get("data_type"), field.get("length"), field.get("comment")});
		}
	}

	private void renderFunctions(Object rawFunctions) {
		selectedFunctionAddresses = new ArrayList<>();
		functionModel.setRowCount(0);
		for (Map<String, Object> function : mapList(rawFunctions)) {
			Map<String, Object> address = function.get("address") instanceof Map<?, ?> map
				? Json.object(map) : null;
			functionModel.addRow(new Object[] {function.get("name"), formatAddress(address),
				function.get("signature")});
			selectedFunctionAddresses.add(address);
		}
	}

	private void renderVtables(Object rawVtables) {
		selectedVtableAddresses = new ArrayList<>();
		vtableModel.setRowCount(0);
		for (Map<String, Object> vtable : mapList(rawVtables)) {
			String vtableName = String.valueOf(vtable.getOrDefault("name", vtable.get("address")));
			for (Map<String, Object> slot : mapList(vtable.get("slots"))) {
				List<Map<String, Object>> relations = mapList(slot.get("parent_relations"));
				if (relations.isEmpty()) {
					vtableModel.addRow(new Object[] {vtableName, slot.get("index"), functionName(slot.get("function")),
						slot.getOrDefault("relation", "introduced"), "", ""});
					selectedVtableAddresses.add(functionAddress(slot.get("function")));
				}
				else {
					for (Map<String, Object> relation : relations) {
						vtableModel.addRow(new Object[] {vtableName, slot.get("index"), functionName(slot.get("function")),
							relation.get("relation"), relation.get("parent_class"), functionName(relation.get("function"))});
						selectedVtableAddresses.add(functionAddress(slot.get("function")));
					}
				}
			}
		}
	}

	private void clearDetails() {
		overview.setText("");
		groupModel.setRowCount(0);
		fieldModel.setRowCount(0);
		functionModel.setRowCount(0);
		vtableModel.setRowCount(0);
		selectedFunctionAddresses = List.of();
		selectedVtableAddresses = List.of();
	}

	private void navigateVtableRow() {
		int row = vtables.getSelectedRow();
		if (row < 0 || row >= selectedVtableAddresses.size()) {
			return;
		}
		navigateToAddress(selectedVtableAddresses.get(row));
	}

	private void navigateFunctionRow() {
		int row = functions.getSelectedRow();
		if (row < 0 || row >= selectedFunctionAddresses.size()) {
			return;
		}
		navigateToAddress(selectedFunctionAddresses.get(row));
	}

	private void applyFilter() {
		String selectedPath = selectedClassPath();
		Set<String> expandedPaths = expandedClassPaths();
		rebuildClassTree(expandedPaths);
		if (selectedPath != null) {
			selectClassPath(selectedPath);
		}
	}

	private void cancelPendingRefresh() {
		synchronized (refreshLock) {
			if (pendingRefresh != null) {
				pendingRefresh.cancel(false);
				pendingRefresh = null;
			}
		}
	}

	private boolean isCurrent(String requestedProgram, long requestedGeneration) {
		return requestedGeneration == generation.get() && requestedProgram.equals(programId);
	}

	private static String formatOffset(Object value) {
		return value == null ? "" : "0x" + Integer.toHexString(number(value).intValue());
	}

	private static String formatAddress(Object value) {
		if (!(value instanceof Map<?, ?> map)) {
			return value == null ? "" : String.valueOf(value);
		}
		Object offset = map.get("offset");
		return offset == null ? Json.stringify(map) : "0x" + offset;
	}

	private static String functionName(Object value) {
		if (!(value instanceof Map<?, ?> map)) {
			return value == null ? "" : String.valueOf(value);
		}
		Object name = map.get("name");
		Object address = map.get("address");
		return name == null ? String.valueOf(address) : name + " @ " + address;
	}

	private static Map<String, Object> functionAddress(Object value) {
		if (!(value instanceof Map<?, ?> map) || !(map.get("address") instanceof Map<?, ?> address)) {
			return null;
		}
		return Json.object(address);
	}

	private static Number number(Object value) {
		return value instanceof Number number ? number : 0;
	}

	private static void configureTable(JTable table) {
		table.setFillsViewportHeight(true);
		table.setAutoResizeMode(JTable.AUTO_RESIZE_LAST_COLUMN);
	}

	private static DefaultTableModel model(String[] columns) {
		return new DefaultTableModel(columns, 0) {
			@Override
			public boolean isCellEditable(int row, int column) {
				return false;
			}
		};
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

	private static String baseIdentity(Map<String, Object> base) {
		Object value = base.get("class_id");
		return value == null ? baseName(base) : String.valueOf(value);
	}

	private static String baseName(Map<String, Object> base) {
		Object value = base.get("name");
		if (value != null) {
			return String.valueOf(value);
		}
		return String.valueOf(base.getOrDefault("class_name", ""));
	}

	private static final class ClassGroup {
		private final Map<String, Object> item;
		private final String name;
		private final String path;
		private final List<Map<String, Object>> members;

		ClassGroup(Map<String, Object> item) {
			this.item = item;
			name = String.valueOf(item.getOrDefault("class_name", item.get("name")));
			path = String.valueOf(item.get("path"));
			members = mapList(item.get("group_structures"));
		}

		boolean matches(String text) {
			if (name.toLowerCase().contains(text) || path.toLowerCase().contains(text)) {
				return true;
			}
			return members.stream().map(Json::stringify).anyMatch(value -> value.toLowerCase().contains(text));
		}

		String name() {
			return name;
		}

		String path() {
			return path;
		}

		String id() {
		Object value = item.get("class_id");
		return value == null ? path : String.valueOf(value);
		}

		List<Map<String, Object>> bases() {
			return mapList(item.get("bases"));
		}

		List<Map<String, Object>> members() {
			return members;
		}

		@Override
		public String toString() {
			return name + "  (" + members.size() + " related structs)";
		}
	}

	private record GroupStruct(String role, String name, String path, Map<String, Object> address,
		String parentPath, String parentName) {
		GroupStruct(Map<String, Object> member, ClassGroup parent) {
			this(String.valueOf(member.get("role")), String.valueOf(member.get("name")),
				member.get("path") == null ? null : String.valueOf(member.get("path")),
				member.get("address") instanceof Map<?, ?> map ? Json.object(map) : null,
				parent.path(), parent.name());
		}

		@Override
		public String toString() {
			String location = address == null ? "" : " @ " + formatAddress(address);
			return role + ": " + name + location + (path == null ? "" : "  " + path);
		}
	}
}
