//Dump every function's decompiled C, call graph and string references to a JSON file.
//@category revagent
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

public class DumpFunctions extends GhidraScript {

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private static String arr(Collection<String> xs) {
        StringBuilder b = new StringBuilder("[");
        boolean first = true;
        for (String x : xs) {
            if (!first) b.append(",");
            first = false;
            b.append('"').append(esc(x)).append('"');
        }
        return b.append("]").toString();
    }

    @Override
    public void run() throws Exception {
        String[] a = getScriptArgs();
        String outPath = a.length > 0 ? a[0] : "functions.json";
        DecompInterface ifc = new DecompInterface();
        ifc.setOptions(new DecompileOptions());
        ifc.openProgram(currentProgram);
        ReferenceManager rm = currentProgram.getReferenceManager();
        PrintWriter w = new PrintWriter(new FileWriter(outPath));
        w.print("[");
        boolean first = true;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            if (f.isExternal()) continue;
            String c = "";
            try {
                DecompileResults r = ifc.decompileFunction(f, 60, monitor);
                if (r != null && r.decompileCompleted()) c = r.getDecompiledFunction().getC();
            } catch (Exception e) {
                c = "";
            }
            Set<String> callers = new TreeSet<>();
            for (Function g : f.getCallingFunctions(monitor)) callers.add(g.getName());
            Set<String> callees = new TreeSet<>();
            for (Function g : f.getCalledFunctions(monitor)) callees.add(g.getName());
            List<String> strs = new ArrayList<>();
            AddressIterator it = rm.getReferenceSourceIterator(f.getBody(), true);
            while (it.hasNext()) {
                Address src = it.next();
                for (Reference ref : rm.getReferencesFrom(src)) {
                    Data d = getDataAt(ref.getToAddress());
                    if (d != null && d.hasStringValue()) strs.add(String.valueOf(d.getValue()));
                }
            }
            if (!first) w.print(",\n");
            first = false;
            w.print("{\"name\":\"" + esc(f.getName())
                + "\",\"entry\":\"0x" + f.getEntryPoint().toString()
                + "\",\"size\":" + f.getBody().getNumAddresses()
                + ",\"is_thunk\":" + f.isThunk()
                + ",\"callers\":" + arr(callers)
                + ",\"callees\":" + arr(callees)
                + ",\"string_refs\":" + arr(strs)
                + ",\"decompiled_c\":\"" + esc(c) + "\"}");
        }
        w.print("]\n");
        w.close();
        ifc.dispose();
        println("DumpFunctions: wrote " + outPath);
    }
}
