package aether.ghidra.headless;

import ghidra.program.model.listing.Program;
import ghidra.framework.model.Project;
import java.util.List;

import aether.ghidra.bridge.BridgeServer;
import aether.ghidra.plugin.AgentProcess;
import aether.ghidra.program.ProgramRegistry;

/** Shared AETHER bridge and agent lifecycle for a headless Ghidra workspace. */
public final class HeadlessAetherRuntime implements AutoCloseable {
	private final ProgramRegistry registry;
	private final BridgeServer bridge;
	private final AgentProcess agent;

	public HeadlessAetherRuntime(Program program, int bridgePort) {
		this(program == null ? List.of() : List.of(program), bridgePort);
	}

	public HeadlessAetherRuntime(List<Program> programs, int bridgePort) {
		registry = new ProgramRegistry(programs);
		bridge = new BridgeServer(registry, bridgePort);
		agent = new AgentProcess();
	}

	public HeadlessAetherRuntime(Project project, Program initialProgram, int bridgePort) {
		registry = new ProgramRegistry(project, initialProgram);
		bridge = new BridgeServer(registry, bridgePort);
		agent = new AgentProcess();
	}

	public void start() {
		bridge.start();
		try {
			agent.start(bridge.getPort());
		}
		catch (RuntimeException error) {
			bridge.stop();
			registry.close();
			throw error;
		}
	}

	public int bridgePort() {
		return bridge.getPort();
	}

	public ProgramRegistry registry() {
		return registry;
	}

	@Override
	public void close() {
		agent.stop();
		bridge.stop();
		registry.close();
	}
}
