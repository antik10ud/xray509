package xray509;

import com.github.difflib.DiffUtils;
import com.github.difflib.algorithm.DiffException;
import com.github.difflib.patch.AbstractDelta;
import com.github.difflib.patch.Patch;
import com.k10ud.certs.CertificateProc;
import com.k10ud.certs.Context;
import com.k10ud.certs.KeyDumper;
import com.k10ud.cli.CliUtil;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;


public class ParsingTest {

    @Test
    public void parseTest() throws IOException {
        AtomicLong failed = new AtomicLong(0);
        boolean update = "!".equals(System.getProperty("UPDATE"));
        Context context = new Context(() -> null);
        System.out.println("current path: " + Paths.get(".").toAbsolutePath().toString());
        Files.list(Paths.get("src/test/resources/samples")).forEach(f -> {
            byte[] data = CliUtil.readData("CERTIFICATE", f.toString());
            String actual = new KeyDumper().toString(data, new CertificateProc(context).parse(data));

            if (update) {
                try {
                    Files.write(Paths.get("src/test/resources/golden", f.getFileName().toString()), actual.getBytes());
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            } else {
                try {
                    String expected = new String(Files.readAllBytes(Paths.get("src/test/resources/golden", f.getFileName().toString())));
                    if (!expected.equals(actual)) {
                        failed.addAndGet(1);
                        System.out.println("*****> " + f);
                        System.out.println("EXPECTED: ");
                        System.out.println(expected);
                        System.out.println("ACTUAL: ");
                        System.out.println(actual);

                        System.out.println("DIFF: ");

                        List<String> original = Arrays.asList(expected.split("\n"));
                        List<String> revised = Arrays.asList(actual.split("\n"));

                        try {
                            Patch<String> patch = DiffUtils.diff(original, revised);
                            for (AbstractDelta<String> delta : patch.getDeltas()) {
                                System.out.println(delta);
                            }
                        } catch (DiffException e) {
                            throw new RuntimeException(e);
                        }


                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
        });
        if (failed.get()>0) {
            throw new RuntimeException("TEST FAILED!");
        }
    }

}