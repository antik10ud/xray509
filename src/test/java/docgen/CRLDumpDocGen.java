package docgen;

import com.k10ud.cli.XrayCRL;


public class CRLDumpDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
        new CRLDumpDocGen().gen("xray-crl");
    }

    public void section10_Usage() {
        String[] args = new String[]{
                "--help"
        };
        outTitle3("Usage");
        outCmd(args, XrayCRL::main);
    }

    public void section20_sample1() {
        String[] args = new String[]{
                "src/test/java/docgen/acaapp2.crl"
        };
        outTitle3("Sample 1");
        out("View File CRL content");
        outCmd(args, XrayCRL::main);
    }
}