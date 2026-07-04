import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class VigilSearchStrings extends GhidraScript {

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
		String pattern = args.length > 0 ? args[0] : "";
		String lowerPattern = pattern.toLowerCase();
		int maxResults = args.length > 1 ? Integer.parseInt(args[1]) : 100;
		long maxBlockBytes = 64L * 1024L * 1024L;
		int truncatedBlocks = 0;

		StringBuilder sb = new StringBuilder();
		sb.append("{\"pattern\":\"").append(esc(pattern)).append("\",");
		sb.append("\"matches\":[");
		int count = 0;

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (monitor.isCancelled() || count >= maxResults) break;
			if (!block.isInitialized()) continue;
			long size = block.getSize();
			if (size > maxBlockBytes) {
				size = maxBlockBytes;
				truncatedBlocks++;
			}
			if (size > Integer.MAX_VALUE) continue;

			byte[] bytes = new byte[(int)size];
			block.getBytes(block.getStart(), bytes);
			StringBuilder cur = new StringBuilder();
			long startOff = 0;

			for (int i = 0; i < bytes.length && count < maxResults; i++) {
				byte b = bytes[i];
				if (b >= 0x20 && b < 0x7f) {
					if (cur.length() == 0) startOff = block.getStart().getOffset() + i;
					cur.append((char)b);
				} else {
					if (cur.length() >= 4) {
						String s = cur.toString();
						if (pattern.isEmpty() || s.toLowerCase().contains(lowerPattern)) {
							if (count > 0) sb.append(",");
							sb.append("{");
							sb.append("\"offset\":\"0x").append(Long.toHexString(startOff)).append("\",");
							sb.append("\"string\":\"").append(esc(s)).append("\",");
							sb.append("\"block\":\"").append(esc(block.getName())).append("\"");
							sb.append("}");
							count++;
						}
					}
					cur.setLength(0);
				}
			}
		}
		sb.append("],\"count\":").append(count).append(",");
		sb.append("\"truncated_blocks\":").append(truncatedBlocks).append("}");
		println("__VIGIL_OUTPUT__" + sb.toString() + "__VIGIL_END__");
	}
}
