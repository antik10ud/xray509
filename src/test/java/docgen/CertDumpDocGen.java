package docgen;

import com.k10ud.cli.XrayCert;


public class CertDumpDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
        new CertDumpDocGen().gen("xray-cert");
    }

    public void section10_Usage() {
        String[] args = new String[]{
                "--help"
        };
        outTitle3("Usage");
        outCmd(args, XrayCert::main);
    }

    public void section20_sample() {
        String[] args = new String[]{
                "src/test/java/docgen/google.pem"
        };
        outTitle3("Sample 1");
        out("View Certificate Content");
        outCmd(args, XrayCert::main);
    }

    public void section30_sample() {
        String[] args = new String[]{
                "src/test/java/docgen/eidas.pem"
        };
        outTitle3("Sample 2");
        out("View EIDAS Certificate Content");
        outCmd(args, XrayCert::main);
    }


    public void section40_sample() {
        String[] args = new String[]{
                "--query", "MATCH Extensions/**/$qcType:=0.4.0.1862.1.6 RETURN $qcType",
                "src/test/java/docgen/eidas.pem"
        };
        outTitle3("Sample 3");
        out("Query certificate elements using the x509 Query Language. You can also use multiple certs to do a certificate filtered search");
        outCmd(args, XrayCert::main);
    }
}