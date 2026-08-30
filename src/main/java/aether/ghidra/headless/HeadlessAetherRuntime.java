package aether.ghidra.headless;

import ghidra.program.model.listing.Program;

import aether.ghidra.bridge.BridgeServer;
import aether.ghidra.plugin.AgentProcess;
import aether.ghidra.program.ProgramRegistry;

/** Shared AETHER bridge and agent lifecycle for a headless Ghidra workspace. */
public final class HeadlessAetherRuntime implements AutoCloseable {
	private final ProgramRegistry registry;
	private final BridgeServer bridge;
	private final AgentProcess agent;

	public HeadlessAetherRuntime(Program program, int bridgePort) {
		registry = new ProgramRegistry(program);
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
