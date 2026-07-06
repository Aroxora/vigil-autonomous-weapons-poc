import ghidra.app.script.GhidraScript;
import java.io.File;
import java.io.FileWriter;

public class VigilGetXRefs extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        File outDir = new File(args.length > 0 ? args[0] : "/tmp");
        if (!outDir.exists()) outDir.mkdirs();
        
        File metaFile = new File(outDir, "program-metadata.json");
        try (FileWriter w = new FileWriter(metaFile)) {
            w.write("{\n");
            w.write("  \"name\": \"" + esc(currentProgram.getName()) + "\",\n");
            w.write("  \"executableFormat\": \"" + esc(currentProgram.getExecutableFormat()) + "\",\n");
            w.write("  \"languageId\": \"" + esc(currentProgram.getLanguageID().toString()) + "\",\n");
            w.write("  \"functionCount\": " + currentProgram.getFunctionManager().getFunctionCount() + "\n");
            w.write("}\n");
        }
    }
    
    private String esc(String v) {
        if (v == null) return "";
        return v.replace("\\", "\\\\").replace("\"", "\\\"");
    }
}
