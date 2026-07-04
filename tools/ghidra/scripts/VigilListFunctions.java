import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class VigilListFunctions extends GhidraScript {

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
		int maxFunctions = args.length > 0 ? Integer.parseInt(args[0]) : 1000;
		int count = 0;
		boolean truncated = false;

		StringBuilder sb = new StringBuilder();
		sb.append("{\"functions\":[");
		boolean first = true;
		FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			if (count >= maxFunctions) {
				truncated = true;
				break;
			}
			if (!first) sb.append(",");
			sb.append("{");
			sb.append("\"name\":\"").append(esc(f.getName())).append("\",");
			sb.append("\"address\":\"").append(f.getEntryPoint().toString()).append("\",");
			sb.append("\"signature\":\"").append(esc(f.getSignature().getPrototypeString())).append("\",");
			sb.append("\"body\":\"").append(esc(f.getBody().toString())).append("\"");
			sb.append("}");
			first = false;
			count++;
		}
		sb.append("],");
		sb.append("\"program\":\"").append(esc(currentProgram.getName())).append("\",");
		sb.append("\"count\":").append(count).append(",");
		sb.append("\"truncated\":").append(truncated).append("}");
		println("__VIGIL_OUTPUT__" + sb.toString() + "__VIGIL_END__");
	}
}
