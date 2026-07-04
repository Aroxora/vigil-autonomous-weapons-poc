import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

public class VigilExportInfo extends GhidraScript {

	private String esc(String s) {
		if (s == null) return "";
		StringBuilder out = new StringBuilder();
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (c == '\\') out.append("\\\\");
			else if (c == '"') out.append("\\\"");
			else if (c == '\n') out.append("\\n");
			else if (c == '\r') out.append("\\r");
			else if (c == '\t') out.append("\\t");
			else if (c < 0x20) out.append(String.format("\\u%04x", (int)c));
			else out.append(c);
		}
		return out.toString();
	}

	@Override
	public void run() throws Exception {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		sb.append("\"program\":\"").append(esc(currentProgram.getName())).append("\",");
		sb.append("\"executable_path\":\"").append(esc(currentProgram.getExecutablePath())).append("\",");
		sb.append("\"format\":\"").append(esc(currentProgram.getExecutableFormat())).append("\",");
		sb.append("\"md5\":\"").append(esc(currentProgram.getExecutableMD5())).append("\",");
		sb.append("\"image_base\":\"").append(currentProgram.getImageBase().toString()).append("\",");
		sb.append("\"language\":\"").append(esc(currentProgram.getLanguage().getLanguageID().getIdAsString())).append("\",");
		sb.append("\"compiler_spec\":\"").append(esc(currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString())).append("\",");

		sb.append("\"functions\":[");
		boolean firstF = true;
		FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function f = iter.next();
			if (!firstF) sb.append(",");
			sb.append("{");
			sb.append("\"name\":\"").append(esc(f.getName())).append("\",");
			sb.append("\"address\":\"").append(f.getEntryPoint().toString()).append("\",");
			sb.append("\"signature\":\"").append(esc(f.getSignature().getPrototypeString())).append("\",");
			sb.append("\"body\":\"").append(esc(f.getBody().toString())).append("\"");
			sb.append("}");
			firstF = false;
		}
		sb.append("],");

		SymbolTable symTable = currentProgram.getSymbolTable();
		sb.append("\"imports\":[");
		boolean firstI = true;
		for (Symbol sym : symTable.getExternalSymbols()) {
			if (monitor.isCancelled()) break;
			if (!firstI) sb.append(",");
			sb.append("{");
			sb.append("\"name\":\"").append(esc(sym.getName())).append("\",");
			sb.append("\"address\":\"").append(sym.getAddress().toString()).append("\"");
			if (sym.getParentSymbol() != null) {
				sb.append(",\"library\":\"").append(esc(sym.getParentSymbol().getName())).append("\"");
			}
			sb.append("}");
			firstI = false;
		}
		sb.append("],");

		sb.append("\"sections\":[");
		boolean firstS = true;
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!firstS) sb.append(",");
			sb.append("{");
			sb.append("\"name\":\"").append(esc(block.getName())).append("\",");
			sb.append("\"start\":\"").append(block.getStart().toString()).append("\",");
			sb.append("\"end\":\"").append(block.getEnd().toString()).append("\",");
			sb.append("\"size\":").append(block.getSize()).append(",");
			sb.append("\"read\":").append(block.isRead()).append(",");
			sb.append("\"write\":").append(block.isWrite()).append(",");
			sb.append("\"execute\":").append(block.isExecute());
			sb.append("}");
			firstS = false;
		}
		sb.append("]}");

		println("__VIGIL_OUTPUT__" + sb.toString() + "__VIGIL_END__");
	}
}
