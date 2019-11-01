package docgen;

import java.io.OutputStream;
import java.io.PrintStream;
import java.lang.reflect.Method;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Comparator;
import java.util.function.Consumer;

import static java.nio.file.Files.newOutputStream;


public abstract class AbstractDumpDocGen {

    private String commandName;
    private PrintStream out;

    void gen(String commandName) throws Exception {
        this.commandName = commandName;
        try (OutputStream f = newOutputStream(Paths.get("doc/" + commandName + ".md"))) {
            out = new PrintStream(f);
            Method[] list = getClass().getMethods();
            Arrays.sort(list, Comparator.comparing(Method::getName));
/*
            outTitle3("Table of Contents");

            for (Method m : list) {
                if (m.getName().startsWith("section")) {
                    out("[" + m.getName() + "](#" + m.getName() + ")");
                }
            }*/


            for (Method m : list) {
                if (m.getName().startsWith("section")) {
                 //   out("<a name=\"" + m.getName() + "\"/>");
                    m.invoke(this);
                }
            }

        }
    }


    void outCmd(String[] args, Consumer<String[]> main) {

        out("```");
        out("$ " + commandName + " " + String.join(" ", args)); //TODO: quote arg when required
        PrintStream org = System.out;
        System.setOut(out);
        main.accept(args);
        System.setOut(org);
        out("```");
    }


    void outTitle3(String s) {
        out("###### " + s);
    }


    void out(String s) {
        out.println(s);
    }

}

