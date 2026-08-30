import ghidra.app.cmd.data.TypeDescriptorModel;
import ghidra.app.cmd.data.rtti.Rtti4Model;
import ghidra.app.cmd.data.rtti.Rtti1Model;
import ghidra.app.cmd.data.rtti.Rtti2Model;
import ghidra.app.cmd.data.rtti.Rtti3Model;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.datatype.microsoft.DataValidationOptions;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;

/** Prints the namespace fields exposed by Ghidra's MSVC RTTI type descriptors. */
public class AetherRttiDescriptorSmoke extends GhidraScript {
    @Override
    public void run() throws Exception {
        DataValidationOptions validation = new DataValidationOptions();
        validation.setValidateReferredToData(true);
        SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(
            currentProgram.getMemory().getAllInitializedAddressSet(), SymbolType.LABEL, true);
        while (symbols.hasNext()) {
            Symbol symbol = symbols.next();
            if (!symbol.getName().contains("RTTI_Complete_Object_Locator")) {
                continue;
            }
            try {
                Rtti4Model rtti4 = new Rtti4Model(currentProgram, symbol.getAddress(), validation);
                TypeDescriptorModel descriptor = rtti4.getRtti0Model();
                println(symbol.getAddress() + " name=" + descriptor.getDescriptorName() +
                    " namespace=" + descriptor.getDescriptorTypeNamespace() +
                    " parent=" + descriptor.getParentNamespace());
                if ("DDImage".equals(descriptor.getDescriptorName())) {
                    Rtti3Model rtti3 = rtti4.getRtti3Model();
                    Rtti2Model rtti2 = rtti3.getRtti2Model();
                    for (int index = 0; index < rtti3.getRtti1Count(); index++) {
                        Rtti1Model base = rtti2.getRtti1Model(index);
                        TypeDescriptorModel baseType = base.getRtti0Model();
                        println("DDImage base[" + index + "]=" + baseType.getDescriptorTypeNamespace() +
                            " numBases=" + base.getNumBases() + " mdisp=" + base.getMDisp());
                    }
                }
            }
            catch (Exception ignored) {
            }
        }
    }
}
