package aether.ghidra.program;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import aether.ghidra.observability.DebugLog;

/**
 * Debounced, single-flight recompute of the persisted class graph. Shared by
 * the GUI plugin (change events) and ProgramRegistry (write capabilities) so
 * both modes coalesce onto one schedule. Identical recomputes write nothing,
 * which keeps the change-event cycle finite.
 */
final class ClassGraphRefresher {
	private static final long DEBOUNCE_SECONDS = 3;

	private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(runnable -> {
		Thread thread = new Thread(runnable, "AETHER-ClassGraphRefresh");
		thread.setDaemon(true);
		return thread;
	});
	private final Object lock = new Object();
	private ScheduledFuture<?> pending;
	private Runnable onComplete;
	private boolean updating;
	private boolean dirtyWhileUpdating;

	void schedule(Program program, Runnable callback) {
		if (program == null || program.isClosed() || !RttiAnalysisStore.hasStoredGraph(program)) {
			return;
		}
		synchronized (lock) {
			onComplete = callback;
			if (updating) {
				// A change arrived while a recompute runs; re-run afterwards so
				// nothing observed mid-flight is lost.
				dirtyWhileUpdating = true;
				return;
			}
			if (pending != null) {
				pending.cancel(false);
			}
			pending = executor.schedule(() -> run(program), DEBOUNCE_SECONDS, TimeUnit.SECONDS);
		}
	}

	private void run(Program program) {
		synchronized (lock) {
			pending = null;
			if (updating || program.isClosed()) {
				return;
			}
			updating = true;
			dirtyWhileUpdating = false;
		}
		Runnable callback;
		synchronized (lock) {
			callback = onComplete;
			onComplete = null;
		}
		try {
			RttiRecoveryRunner.refreshClassGraph(program, TaskMonitor.DUMMY);
			if (callback != null) {
				callback.run();
			}
		}
		catch (Exception error) {
			DebugLog.debug(this, "class graph refresh failed: " + error.getMessage());
		}
		finally {
			boolean again;
			synchronized (lock) {
				updating = false;
				again = dirtyWhileUpdating && !program.isClosed();
				dirtyWhileUpdating = false;
			}
			if (again) {
				schedule(program, null);
			}
		}
	}

	void shutdown() {
		synchronized (lock) {
			if (pending != null) {
				pending.cancel(false);
				pending = null;
			}
		}
		executor.shutdownNow();
	}
}
