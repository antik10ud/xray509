/*
 * Copyright (c) 2019 David Castañón <antik10ud@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package com.k10ud.certs;

import com.k10ud.asn1.x509_certificate.AlgorithmIdentifier;
import com.k10ud.certs.extensions.*;
import com.k10ud.certs.util.ASN1Helper;
import com.k10ud.certs.util.Base64;
import com.k10ud.certs.util.StringUtils;
import com.k10ud.help.QueryableMap;
import org.openmuc.jasn1.ber.types.BerObjectIdentifier;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

public class Context {
    private final Properties oids;
    private final Map<String, Item> trustedList;
    private final Map<String, byte[]> trustedListByAKI;
    private final Map<String, ExtensionProc> extProc;
    private final DefaultProc defaultExtensionProcessor;

    public interface Config {
        Path getTLPropertiesFile();
    }

    private final Config cfg;

    public Context(Config cfg) throws IOException {
        this.extProc = new HashMap<>();
        this.oids = new Properties();
        this.cfg = cfg;
        this.trustedList = new HashMap<>();
        this.trustedListByAKI = new HashMap<>();

        loadOids();
        loadTrustedList();
        registerExtensions();

        defaultExtensionProcessor = new DefaultProc();
    }


    private void registerExtensions() {
        registerExtension("2.5.29.32", new PolicyProc());
        registerExtension("1.3.6.1.5.5.7.1.3", new QCStatementProc());
        registerExtension("2.5.29.17", new SubjectAltNameProc());
        registerExtension("2.5.29.18", new IssuerAltNameProc());
        registerExtension("2.5.29.37", new ExtKeyUsageProc());
        registerExtension("2.5.29.15", new KeyUsageProc());
        registerExtension("2.5.29.19", new BasicConstraintsProc());
        registerExtension("2.5.29.31", new CRLDistPointsProc());
        registerExtension("1.3.6.1.5.5.7.1.1", new AIAProc());
        registerExtension("1.3.6.1.5.5.7.1.2", new BiometricInfoProc());
        registerExtension("2.5.29.9", new SubjectDirAttrProc());
        registerExtension("2.16.840.1.113730.1.1", new NetscapeCertUsageProc());
        registerExtension("2.5.29.16", new PrivateKeyUsagePeriodProc());
        registerExtension("2.5.29.30", new NameConstraintsProc());
        registerExtension("1.2.840.113533.7.65.0", new EntrustVersInfoProc());
        registerExtension("2.16.724.1.2.2.4.1", new PersonalDataInfoProc());

        registerExtension("2.5.29.21", new CRLReasonCodeProc());
        registerExtension("2.5.29.24", new CRLInvalidityDateProc());
        registerExtension("2.5.29.29", new CRLCertificateIssuerProc());

        registerExtension("2.5.29.35", new AuthorityKeyIdentifierProc());
        registerExtension("2.5.29.14", new SubjectKeyIdentifierProc());
        registerExtension("2.5.29.20", new CRLNumberProc());
        registerExtension("2.5.29.28", new CRLCertificateIssuerProc());

        registerExtension("2.5.29.60", new ExpiredCertsOnCRLProc());

        registerExtension("1.3.6.1.4.1.11129.2.4.2", new CertificateTransparencyProc());

        registerExtension("2.23.140.3.1",new CabfOrganizationIdentifierProc());


    }

    private void loadOids() {
        try (
                InputStreamReader reader = new InputStreamReader(CertificateProc.class.getResourceAsStream("/oids.properties"), "UTF-8")
        ) {
            oids.load(reader);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void loadTrustedList() throws IOException {
        if (cfg.getTLPropertiesFile() == null)
            return;
        Context precontext = new Context(() -> null);
        try (InputStream is = Files.newInputStream(cfg.getTLPropertiesFile())) {
            Properties p = new Properties();
            p.load(is);
            for (Object k : p.keySet()) {
                String k1 = (String) k;
                if (k1.startsWith("tl.cert.id.")) {
                    String id = p.getProperty(k1);
                    String prefix = "tl.cert." + id + ".";
                    String cert = p.getProperty(prefix + "x509");
                    byte[] bytes = Base64.decode(cert);
                    Item item = new Item();
                    item.prop("TSP Trade Name", p.getProperty(prefix + "service.tsp-tradename"));
                    item.prop("TSP Name", p.getProperty(prefix + "service.tsp-name"));
                    item.prop("Name", p.getProperty(prefix + "service.name"));
                    item.prop("Type", p.getProperty(prefix + "service.type"));
                    item.prop("Electronic address", p.getProperty(prefix + "service.e-address"));
                    item.prop("Address", p.getProperty(prefix + "service.address"));
                    item.prop("Source", p.getProperty(prefix + "service.source"));
                    item.prop("@cert", cert);
                    Item eeitem = new Item();
                    for (int i = 0; i < 10; i++) {
                        String eeid = p.getProperty(prefix + "ee.qualifiers." + i + ".id", "");
                        if (eeid.isEmpty())
                            break;
                        String condition = p.getProperty(prefix + "ee.qualifiers." + i + ".condition", "");
                        eeitem.prop(eeid, condition);
                    }
                    if (eeitem.size() > 0)
                        item.prop("Qualifiers", eeitem);


                    trustedList.put(certId(bytes), item);

                    {
                        Item certItems = new CertificateProc(precontext).parse(bytes);
                        QueryableMap map = new QueryableMap(certItems);
                        List<String> ski = map.q("Extensions/*/2.5.29.14/Value=(*)");
                        if (ski.size() > 0) {
                            trustedListByAKI.put(ski.get(0), bytes);
                        }
                    }
                }
            }
            //log.info("loaded {} trusted certs");
        } catch (Exception x) {
            System.out.println("TSL Load Fail: " + cfg.getTLPropertiesFile());
        }
    }

    public void registerExtension(String oid, ExtensionProc processor) {
        extProc.put(oid, processor);
    }

    public String oidName(String oid) {
        return oids.getProperty(oid, oid);
    }

    public TaggedString nameAndOid(String oid) {
        TaggedString ts = new TaggedString(oid);
        String desc = getOidDesc(oid);
        if (desc.length() > 0)
            ts.addTag("desc", desc);
        return ts;
    }

    private String getOidDesc(String oid) {
        String desc = oids.getProperty(oid, "-");
        if (desc.length() == 0)
            return "";
        if (!"-".equals(desc))
            return desc;

        boolean tryfetch = false;

        if (tryfetch) {
            desc = get(oid);
            if (desc.length() > 0) {
                System.out.println(oid + "=" + desc);
                oids.setProperty(oid, desc);
                return desc;
            }
        }

        String ooid = oid;
        for (; ; ) {
            int i = oid.lastIndexOf(".");
            if (i > 0) {
                String base = oid.substring(0, i);
                String rest = ooid.substring(i + 1);
                oid = base;
                String basedesc = oids.getProperty(oid, tryfetch ? "-" : "");
                if ("-".equals(basedesc)) {
                    basedesc = get(oid);
                    if (basedesc.length() > 0) {
                        System.out.println(oid + "=" + basedesc);
                    }
                    oids.setProperty(oid, basedesc);
                }
                if (basedesc.length() > 0) {
                    desc = basedesc;// + "(" + rest + ")";
                    return desc;
                }
                if (tryfetch)
                    oids.setProperty(oid, "");
            } else {
                if (tryfetch)
                    oids.setProperty(oid, "");
                return "";
            }
        }
    }


    private String get(String oid) {
        String desc = "";
        try (InputStream is = new URL("http://oid-info.com/get/" + oid).openStream()) {
            StringBuffer sb = new StringBuffer();
            byte[] buffer = new byte[65535];
            for (; ; ) {
                int n = is.read(buffer);
                if (n == -1)
                    break;
                sb.append(new String(buffer, 0, n));
            }
            {
                int t0 = sb.indexOf("<tt>");
                if (t0 > 0) {
                    int t1 = sb.indexOf("</tt>", t0);
                    if (t1 > 0) {
                        desc = sb.substring(t0 + 4, t1).trim();

                    }
                }
            }
            if (desc.length() < 10) {
                String s = "width=\"315\">\n" +
                        "            <br>";
                int t0 = sb.indexOf(s);
                if (t0 > 0) {
                    int t1 = sb.indexOf("\n<br><br>", t0);
                    if (t1 > 0) {
                        desc = sb.substring(t0 + s.length(), t1).trim();
                        desc = desc.replaceAll("<[^<]*>", "");
                    }
                }
            }
            if (desc == null)
                desc = "";

            desc = StringUtils.unescapeHtml(desc.replace("\n", " ").trim());

        } catch (Exception e) {
            desc = "";
        }

        return desc;
    }

    public ExtensionProc extensionProcessor(String oid) {

        ExtensionProc processor = extProc.get(oid);
        if (processor == null)
            return defaultExtensionProcessor;
        return processor;
    }


    public TaggedString nameAndOid(BerObjectIdentifier identifier) {
        if (identifier == null)
            return null;
        return nameAndOid(identifier.toString());
    }

    private String certId(byte[] certificate) {
        return ASN1Helper.bytesToHex(ASN1Helper.hash("SHA-256", certificate), "");
    }

    public Item trustedListInfo(byte[] certificate) {
        if (certificate == null)
            return null;
        return trustedList.get(certId(certificate));
    }

    public byte[] trustedListInfoByAKI(String aki) {
        if (aki == null)
            return null;
        return trustedListByAKI.get(aki);
    }

    public Object algorithm(AlgorithmIdentifier algorithm) {
        return nameAndOid(algorithm.algorithm);
    }
}
