package aether.ghidra.plugin.ui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.event.ActionEvent;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;

import aether.ghidra.bridge.Json;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.framework.plugintool.PluginTool;
import docking.WindowPosition;

/** Persistent dockable chatbot surface for one session-scoped Ghidra Program. */
public final class ChatProvider extends ComponentProviderAdapter {
	public interface Backend {
		Map<String, Object> startChat(String programId, String message, Map<String, Object> address);
		Map<String, Object> chatJob(String jobId);
		Map<String, Object> cancelChat(String jobId);
		Map<String, Object> sessionState(String programId);
		void clearSession(String programId);
	}

	private final Backend backend;
	private final Consumer<String> status;
	private final JPanel root = new JPanel(new BorderLayout(6, 6));
	private final JTextArea transcript = new JTextArea();
	private final JTextArea composer = new JTextArea(4, 60);
	private final JButton send = new JButton("Send");
	private final JButton cancel = new JButton("Cancel");
	private final JButton clear = new JButton("Clear");
	private final JLabel contextLabel = new JLabel("No program selected");
	private final ExecutorService executor = Executors.newSingleThreadExecutor(r -> {
		Thread thread = new Thread(r, "aether-chat-ui");
		thread.setDaemon(true);
		return thread;
	});
	private final AtomicLong generation = new AtomicLong();
	private volatile Future<?> activeFuture;
	private volatile String activeJobId;
	private volatile String programId;
	private volatile Map<String, Object> address;

	public ChatProvider(PluginTool tool, String owner, Backend backend, Consumer<String> status) {
		super(tool, "AETHER Chat", owner);
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		this.backend = backend;
		this.status = status;
		transcript.setEditable(false);
		transcript.setLineWrap(true);
		transcript.setWrapStyleWord(true);
		transcript.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
		composer.setLineWrap(true);
		composer.setWrapStyleWord(true);
		composer.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));
		send.addActionListener(this::sendMessage);
		cancel.addActionListener(event -> cancelRequest());
		clear.addActionListener(event -> clearConversation());
		cancel.setEnabled(false);
		root.setBorder(BorderFactory.createEmptyBorder(6, 6, 6, 6));
		buildUi();
	}

	@Override
	public javax.swing.JComponent getComponent() {
		return root;
	}

	public void selectProgram(String nextProgramId) {
		if (nextProgramId == null || nextProgramId.equals(programId)) {
			return;
		}
		if (activeJobId != null) {
			cancelRequest();
		}
		programId = nextProgramId;
		address = null;
		contextLabel.setText("Program: " + nextProgramId);
		long requestGeneration = generation.incrementAndGet();
		activeFuture = executor.submit(() -> loadSession(nextProgramId, requestGeneration));
	}

	public void showDockable() {
		if (!isInTool()) {
			addToTool();
		}
		setVisible(true);
		toFront();
	}

	public void setContext(String nextProgramId, Map<String, Object> nextAddress) {
		if (nextProgramId != null && !nextProgramId.equals(programId)) {
			selectProgram(nextProgramId);
		}
		programId = nextProgramId;
		address = nextAddress;
		contextLabel.setText(nextAddress == null
			? "Program: " + nextProgramId
			: "Program: " + nextProgramId + "  Address: " + nextAddress);
		showDockable();
	}

	public void programClosed(String closedProgramId) {
		if (!closedProgramId.equals(programId)) {
			return;
		}
		cancelRequest();
		programId = null;
		address = null;
		generation.incrementAndGet();
		setTranscript("Program closed. Select another program to continue.");
		contextLabel.setText("No program selected");
	}

	public void close() {
		cancelRequest();
		executor.shutdownNow();
		if (isInTool()) {
			removeFromTool();
		}
	}

	private void buildUi() {
		JPanel header = new JPanel(new BorderLayout(6, 0));
		header.add(new JLabel("AETHER Chat"), BorderLayout.WEST);
		header.add(contextLabel, BorderLayout.CENTER);
		header.add(clear, BorderLayout.EAST);
		root.add(header, BorderLayout.NORTH);

		JScrollPane transcriptScroll = new JScrollPane(transcript);
		transcriptScroll.setPreferredSize(new Dimension(560, 360));
		root.add(transcriptScroll, BorderLayout.CENTER);

		JPanel composerPanel = new JPanel(new BorderLayout(6, 0));
		composerPanel.add(new JScrollPane(composer), BorderLayout.CENTER);
		JPanel actions = new JPanel(new FlowLayout(FlowLayout.RIGHT, 4, 0));
		actions.add(cancel);
		actions.add(send);
		composerPanel.add(actions, BorderLayout.SOUTH);
		root.add(composerPanel, BorderLayout.SOUTH);
	}

	private void sendMessage(ActionEvent ignored) {
		String message = composer.getText().trim();
		if (message.isEmpty() || activeJobId != null) {
			return;
		}
		if (programId == null) {
			append("SYSTEM", "No active Ghidra Program is selected.");
			status.accept("AETHER chat needs an active Ghidra Program");
			return;
		}
		String requestProgram = programId;
		Map<String, Object> requestAddress = address;
		composer.setText("");
		append("USER", message);
		setBusy(true);
		long requestGeneration = generation.incrementAndGet();
		activeFuture = executor.submit(() -> runChat(requestProgram, requestAddress, message, requestGeneration));
	}

	private void runChat(String requestProgram, Map<String, Object> requestAddress, String message, long requestGeneration) {
		String jobId = null;
		String lastProgress = "";
		try {
			Map<String, Object> started = backend.startChat(requestProgram, message, requestAddress);
			jobId = String.valueOf(started.get("job_id"));
			activeJobId = jobId;
			if (generation.get() != requestGeneration) {
				backend.cancelChat(jobId);
				activeJobId = null;
				return;
			}
			while (true) {
				if (generation.get() != requestGeneration) {
					return;
				}
				Map<String, Object> job = backend.chatJob(jobId);
				String state = String.valueOf(job.get("state"));
				if ("queued".equals(state) || "running".equals(state)) {
					Map<String, Object> progress = objectMap(job.get("progress"));
					if (!progress.isEmpty()) {
						String progressKey = Json.stringify(progress);
						if (!progressKey.equals(lastProgress)) {
							lastProgress = progressKey;
							postChat(requestProgram, jobId, () -> renderProgress(progress));
						}
					}
					Thread.sleep(250L);
					continue;
				}
				if ("completed".equals(state)) {
					Map<String, Object> result = objectMap(job.get("result"));
					String answer = String.valueOf(result.getOrDefault("final_analysis", ""));
					List<?> toolCalls = result.get("tool_calls") instanceof List<?> list ? list : List.of();
					Object history = result.get("conversation_history");
					postChat(requestProgram, jobId, () -> {
						if (history instanceof List<?>) {
							renderHistory(history);
						}
						else {
							if (!answer.isBlank()) {
								append("AETHER", answer);
							}
							appendToolCalls(toolCalls);
						}
					});
				}
				else {
					postChat(requestProgram, jobId, () ->
						append("AETHER ERROR", String.valueOf(job.getOrDefault("error", "Chat " + state))));
				}
				return;
			}
		}
		catch (InterruptedException error) {
			Thread.currentThread().interrupt();
		}
		catch (RuntimeException error) {
			post(requestGeneration, () -> append("AETHER ERROR", error.getMessage()));
		}
		finally {
			String finishedJobId = jobId;
			postChat(requestProgram, finishedJobId, () -> {
				activeJobId = null;
				setBusy(false);
			});
		}
	}

	private void loadSession(String requestedProgram, long requestGeneration) {
		try {
			Map<String, Object> session = backend.sessionState(requestedProgram);
			post(requestGeneration, () -> renderHistory(session.get("conversation_history")));
		}
		catch (RuntimeException error) {
			post(requestGeneration, () -> append("AETHER ERROR", error.getMessage()));
		}
	}

	private void cancelRequest() {
		String jobId = activeJobId;
		if (jobId == null) {
			generation.incrementAndGet();
			setBusy(false);
			append("SYSTEM", "Chat cancellation requested before the job started.");
			return;
		}
		long requestGeneration = generation.incrementAndGet();
		activeJobId = null;
		setBusy(false);
		executor.submit(() -> {
			try {
				backend.cancelChat(jobId);
				post(requestGeneration, () -> append("SYSTEM", "Chat cancellation requested."));
			}
			catch (RuntimeException error) {
				post(requestGeneration, () -> append("AETHER ERROR", error.getMessage()));
			}
		});
	}

	private void clearConversation() {
		if (programId == null || activeJobId != null) {
			return;
		}
		String requestedProgram = programId;
		long requestGeneration = generation.incrementAndGet();
		executor.submit(() -> {
			try {
				backend.clearSession(requestedProgram);
				post(requestGeneration, () -> setTranscript("Conversation cleared."));
			}
			catch (RuntimeException error) {
				post(requestGeneration, () -> append("AETHER ERROR", error.getMessage()));
			}
		});
	}

	private void renderHistory(Object rawHistory) {
		setTranscript("");
		if (!(rawHistory instanceof List<?> history)) {
			return;
		}
		for (Object raw : history) {
			Map<String, Object> message = objectMap(raw);
			String role = String.valueOf(message.getOrDefault("role", "assistant"));
			if ("user".equals(role)) {
				append("USER", String.valueOf(message.getOrDefault("content", "")));
			}
			else if ("assistant".equals(role)) {
				String content = String.valueOf(message.getOrDefault("content", ""));
				if (!content.isBlank()) {
					append("AETHER", content);
				}
				appendToolCalls(message.get("tool_calls"));
			}
			else if ("tool".equals(role)) {
				append("TOOL RESULT", String.valueOf(message.getOrDefault("content", "")));
			}
		}
	}

	private void renderProgress(Map<String, Object> progress) {
		Object history = progress.get("conversation_history");
		if (history instanceof List<?>) {
			renderHistory(history);
		}
	}

	private void appendToolCalls(Object rawToolCalls) {
		if (!(rawToolCalls instanceof List<?> toolCalls)) {
			return;
		}
		for (Object rawCall : toolCalls) {
			Map<String, Object> call = objectMap(rawCall);
			StringBuilder details = new StringBuilder();
			details.append("Name: ").append(toolName(call));
			if (call.containsKey("arguments") || call.containsKey("function")) {
				details.append("\nArguments: ").append(formatArguments(toolArguments(call)));
			}
			if (call.containsKey("result")) {
				details.append("\nResult:\n").append(String.valueOf(call.get("result")));
			}
			append("TOOL CALL", details.toString());
		}
	}

	private static String toolName(Map<String, Object> call) {
		Object name = call.get("name");
		if (name != null) {
			return String.valueOf(name);
		}
		Map<String, Object> function = objectMap(call.get("function"));
		return String.valueOf(function.getOrDefault("name", "unknown"));
	}

	private static Object toolArguments(Map<String, Object> call) {
		if (call.containsKey("arguments")) {
			return call.get("arguments");
		}
		return objectMap(call.get("function")).get("arguments");
	}

	private static String formatArguments(Object arguments) {
		if (arguments instanceof String text) {
			try {
				return Json.stringify(Json.parse(text));
			}
			catch (RuntimeException ignored) {
				return text;
			}
		}
		return Json.stringify(arguments);
	}

	private void setBusy(boolean busy) {
		send.setEnabled(!busy);
		cancel.setEnabled(busy);
		clear.setEnabled(!busy);
		composer.setEnabled(!busy);
		status.accept(busy ? "AETHER chat is running..." : "AETHER chat is ready");
	}

	private void append(String speaker, String text) {
		if (transcript.getText().length() > 0) {
			transcript.append("\n\n");
		}
		transcript.append(speaker + ":\n" + String.valueOf(text));
		transcript.setCaretPosition(transcript.getDocument().getLength());
	}

	private void setTranscript(String text) {
		transcript.setText(text);
		transcript.setCaretPosition(transcript.getDocument().getLength());
	}

	private void post(long requestGeneration, Runnable action) {
		SwingUtilities.invokeLater(() -> {
			if (generation.get() == requestGeneration) {
				action.run();
			}
		});
	}

	private void postChat(String requestProgram, String requestJobId, Runnable action) {
		SwingUtilities.invokeLater(() -> {
			if (requestProgram.equals(programId) &&
				(requestJobId == null || requestJobId.equals(activeJobId))) {
				action.run();
			}
		});
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> objectMap(Object value) {
		return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
	}
}
