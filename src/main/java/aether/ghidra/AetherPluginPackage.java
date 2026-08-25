package aether.ghidra;

import ghidra.framework.plugintool.util.PluginPackage;

/** Registers the extension's plugin package with Ghidra's plugin manager. */
public class AetherPluginPackage extends PluginPackage {
	public static final String NAME = "AETHER";

	public AetherPluginPackage() {
		super(NAME, null, "AETHER Ghidra integration", PluginPackage.EXPERIMENTAL_PRIORITY);
	}
}
