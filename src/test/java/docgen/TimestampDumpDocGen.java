package docgen;

import com.k10ud.cli.XrayCRL;
import com.k10ud.cli.XrayTimestamp;


public class TimestampDumpDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
       new TimestampDumpDocGen().gen("xray-ts");
    }

    public void section10_Usage() {
        String[] args = new String[]{
                "--help"
        };
        outTitle3("Usage");
        outCmd(args, XrayTimestamp::main);
    }

    public void section20_sample1() {
        String[] args= new String[]{
                "--cert-path",
                "--dump",
                "-o", "/tmp/ts",
                "--source-text","data",
                "http://tsa.belgium.be/connect"
        };
        outTitle3("Sample 1");
        out("Generate a new digital timestamp of the text 'data' and view the request, response and provided timestamp issuer cert chain. Save the request and response at /tmp/ts");
        outCmd(args, XrayTimestamp::main);
    }



}