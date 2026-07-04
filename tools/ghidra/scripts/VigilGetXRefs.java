import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class VigilGetXRefs extends GhidraScript {

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
			println("__VIGIL_OUTPUT__{\"error\":\"Address required\"}__VIGIL_END__");
			return;
		}

		Address addr = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(args[0]);
		ReferenceManager refMgr = currentProgram.getReferenceManager();

		StringBuilder sb = new StringBuilder();
		sb.append("{");
		sb.append("\"address\":\"").append(addr.toString()).append("\",");

		sb.append("\"references_to\":[");
		boolean firstTo = true;
		for (Reference ref : refMgr.getReferencesTo(addr)) {
			if (monitor.isCancelled()) break;
			if (!firstTo) sb.append(",");
			sb.append("{");
			sb.append("\"from\":\"").append(ref.getFromAddress().toString()).append("\",");
			sb.append("\"type\":\"").append(ref.getReferenceType().getName()).append("\"");
			Function func = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
			if (func != null) sb.append(",\"function\":\"").append(esc(func.getName())).append("\"");
			sb.append("}");
			firstTo = false;
		}
		sb.append("],");

		sb.append("\"references_from\":[");
		boolean firstFrom = true;
		for (Reference ref : refMgr.getReferencesFrom(addr)) {
			if (monitor.isCancelled()) break;
			if (!firstFrom) sb.append(",");
			sb.append("{");
			sb.append("\"to\":\"").append(ref.getToAddress().toString()).append("\",");
			sb.append("\"type\":\"").append(ref.getReferenceType().getName()).append("\"");
			sb.append("}");
			firstFrom = false;
		}
		sb.append("]}");

		println("__VIGIL_OUTPUT__" + sb.toString() + "__VIGIL_END__");
	}
}
