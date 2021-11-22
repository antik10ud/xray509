
package com.k10ud.cli;

import com.k10ud.certs.Context;
import com.k10ud.certs.IItemDumper;
import com.k10ud.certs.Item;
import com.k10ud.certs.KeyDumper;
import com.k10ud.certs.util.Exceptions;
import com.k10ud.certs.util.ItemHelper;
import com.k10ud.xray509.blockchain.model.DCRL;
import org.web3j.crypto.Credentials;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.DefaultGasProvider;
import picocli.CommandLine;

import java.io.IOException;
import java.math.BigInteger;

import static com.k10ud.cli.DCRLUtils.DCRL_ETHEREUM;
import static picocli.CommandLine.populateCommand;
import static picocli.CommandLine.usage;

public class XrayDCRL {
    @CommandLine.Command(name = "xray-dcrs",
            header = "xray-dcrs 0.0.1",
            showDefaultValues = true,
            description = "x509 decentralized certificate revocation store"
    )
    public static class Args extends CommonArgs {
        @CommandLine.Parameters(arity = "1", paramLabel = "SOURCE", description = "X509Certificate with dcrl extension")
        private String[] inputFile;
        @CommandLine.Option(names = {"--http-service"}, description = "Ethereum JSON-RPC Service Address")
        public String httpService;
    }


    public static void main(String[] args) {
        Context context;
        try {
            context = new Context(() -> null);
        } catch (IOException e) {
            throw new RuntimeException("Cannot load context");
        }
        Args app = null;
        try {
            app = populateCommand(new Args(), args);
        } catch (Exception x) {
            System.err.println(x.getMessage());
            usage(new Args(), System.err);
            System.exit(-1);
        }
        if (app.helpRequested) {
            usage(new Args(), System.out);
        } else {
            IItemDumper dumper = CliUtil.dumper(app);

            for (String i : app.inputFile) {
                StreamFiles sf = new StreamFiles(i);
                while (sf.hasMore()) {
                    String next = sf.next();
                    try {
                        Item items = processCert(app, context, next);
                        System.out.println(dumper.toString(null, items));
                    } catch (Exception e) {
                        System.err.println(app.inputFile + ": " + Exceptions.getSmartExceptionMessage(e));
                    }
                }
            }

        }
    }


    private static Item processCert(Args app, Context context, String f) {
        Item run = new Item();
        byte[] data = CliUtil.readData("CERTIFICATE", f);
        if (data == null) {
            run.prop("error", "cannot load certificate from " + f);
            return run;
        }
        DCRLUtils.DCRLContracts contracts = DCRLUtils.extractContracts(context, data);
        if (contracts == null) {
            return run;
        }
        run.prop("skid", KeyDumper.toHex(contracts.skid));
        for (String contractURI : contracts.contractAddress) {
            Item entry = new Item();
            if (contractURI == null || !contractURI.startsWith(DCRL_ETHEREUM)) {
                entry.prop("error", "unsupported smart contract " + contractURI);
                continue;
            }
            String contractAdddress = contractURI.substring(DCRL_ETHEREUM.length());
            Web3j web3 = Web3j.build(new HttpService(app.httpService != null ? app.httpService : "http://localhost:8545/"));
            Credentials credentials = Credentials.create("00000000000000000000000000000000");
            DCRL contract = DCRL.load(contractAdddress, web3, credentials, new DefaultGasProvider());
            boolean revoked;
            try {
                revoked = contract.has(new BigInteger(1, contracts.skid)).send();
                entry.prop("revoked", revoked);
            } catch (Exception e) {
                entry.prop("error", "smartc entry call: " + Exceptions.getSmartExceptionMessage(e));
            }

            run.prop(contractURI, entry);

        }
        return run;
    }


}