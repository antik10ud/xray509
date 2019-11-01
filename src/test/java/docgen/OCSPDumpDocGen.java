package docgen;

import com.k10ud.cli.XrayOCSP;
import com.k10ud.cli.XrayTimestamp;


public class OCSPDumpDocGen extends AbstractDumpDocGen {

    public static void main(String[] args) throws Exception {
       new OCSPDumpDocGen().gen("xray-ocsp");
    }

    public void section10_Usage() {
        String[] args = new String[]{
                "--help"
        };
        outTitle3("Usage");
        outCmd(args, XrayOCSP::main);

        out("![Example](xray-ocsp.svg)");

    }

    public void section20_sample() {
        String[] args= new String[]{
                "--cert", "src/test/java/docgen/google.pem"
        };
        outTitle3("Sample 1");
        out("OCSP of provided certificate. Issuer is automagically determined");
        outCmd(args, XrayOCSP::main);
    }

    public void section30_sample() {
        String[] args= new String[]{
                "--cert", "tls:www.facebook.com"
        };
        outTitle3("Sample 2");
        out("OCSP of provided TLS certificate of the Facebook site");
        outCmd(args, XrayOCSP::main);
    }


    public void section40_sample() {
        String[] args= new String[]{
                "--issuer-cert","http://pki.goog/gsr2/GTS1O1.crt",
                "--ocsp-server","http://ocsp.pki.goog/gts1o1",
                "--serial", "0x00ed7f80a1379302560800000000190dcd"
        };

        outTitle3("Sample 3");
        out("OCSP via certificate serialnumber and issuer");
        outCmd(args, XrayOCSP::main);
    }




}