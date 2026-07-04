import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;

public class VigilDecompile extends GhidraScript {

	private String esc(String s) {
		if (s == null) return "";
		return s.replace("\\", "\\\\")
			.replace("\"", "\\\"")
			.replace("\n", "\\n")
			.replace("\r", "\\r")
			.replace("\t", "\\t");
	}

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("__VIGIL_OUTPUT__{\"error\":\"Function address or name required\"}__VIGIL_END__");
			return;
		}

		String target = args[0];
		Function function = null;

		try {
			Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(target);
			function = currentProgram.getFunctionManager().getFunctionAt(addr);
		} catch (Exception e) {
			// Fall back to lookup by function name below.
		}

		if (function == null) {
			for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
				if (f.getName().equals(target)) {
					function = f;
					break;
				}
			}
		}

		if (function == null) {
			println("__VIGIL_OUTPUT__{\"error\":\"Function not found: " + esc(target) + "\"}__VIGIL_END__");
			return;
		}

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);
		DecompileResults dcr = decomp.decompileFunction(function, 30, monitor);

		StringBuilder sb = new StringBuilder();
		sb.append("{");
		sb.append("\"name\":\"").append(esc(function.getName())).append("\",");
		sb.append("\"address\":\"").append(function.getEntryPoint().toString()).append("\",");
		sb.append("\"signature\":\"").append(esc(function.getSignature().getPrototypeString())).append("\",");

		if (dcr.decompileCompleted()) {
			sb.append("\"code\":\"").append(esc(dcr.getDecompiledFunction().getC())).append("\"");
		} else {
			sb.append("\"error\":\"").append(esc(dcr.getErrorMessage())).append("\"");
		}
		sb.append("}");

		decomp.dispose();
		println("__VIGIL_OUTPUT__" + sb.toString() + "__VIGIL_END__");
	}
}
