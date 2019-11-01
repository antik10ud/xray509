package docgen;

import com.k10ud.cli.XrayTimestamp;
import com.k10ud.cli.XrayTimestampCheck;


public class TimestampCheckDumpDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
        new TimestampCheckDumpDocGen().gen("xray-ts-chk");
    }

    public void section10_Usage() {
        String[] args = new String[]{
                "--help"
        };
        outTitle3("Usage");
        outCmd(args, XrayTimestampCheck::main);
    }

    public void section20_sample2() {
        XrayTimestamp.main(new String[]{
                "--cert-path",
                "--dump",
                "-o", "/tmp/ts",
                "--source-text", "data",
                "http://tsa.belgium.be/connect"
        });

        String[] args = new String[]{
                "--dump",
                "--data-text", "data",
                "--tsq", "/tmp/ts.tsq",
                "--tsr", "/tmp/ts.tsr",
        };
        outTitle3("Sample 1");
        out("Check timestamp request and response data");
        outCmd(args, XrayTimestampCheck::main);
    }


}