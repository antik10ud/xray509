
package com.k10ud.cli;

import com.k10ud.certs.Context;
import com.k10ud.certs.KeyDumper;
import com.k10ud.certs.util.Exceptions;
import com.k10ud.xray509.blockchain.model.DCRL;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;
import org.web3j.protocol.Web3j;
import org.web3j.protocol.core.methods.response.TransactionReceipt;
import org.web3j.protocol.http.HttpService;
import org.web3j.tx.gas.StaticGasProvider;
import picocli.CommandLine;

import java.io.IOException;
import java.math.BigInteger;

import static com.k10ud.cli.DCRLUtils.DCRL_ETHEREUM;
import static picocli.CommandLine.populateCommand;
import static picocli.CommandLine.usage;

public class XrayDCRLRevoke {


    @CommandLine.Command(name = "xray-dcrl-publish",
            header = "xray-dcrl-publish 0.0.1",
            showDefaultValues = true,
            description = "Decentralized Certificate Revocation Log DCRL publisher"
    )
    public static class Args {
        @CommandLine.Option(names = {"-h", "--help"}, usageHelp = true,
                description = "Displays this help message and quits.")
        public boolean helpRequested = false;
        public Context context;


        @CommandLine.Parameters(arity = "1", paramLabel = "SOURCE", description = "X509Certificate with dcrl extension")
        private String[] inputFile;
        @CommandLine.Option(names = {"--wallet-pass"}, description = "Wallet password... ONLY FOR TESTING")
        public String wpass;
        @CommandLine.Option(required = true, names = {"--wallet-source"}, description = "Wallet file source")
        public String wsource;
        @CommandLine.Option(names = {"--gas-price"}, description = "Tx Gas Price, -1 auto estimate")
        public BigInteger gasPrice = BigInteger.valueOf(-1);
        @CommandLine.Option(names = {"--gas-limit"}, description = "Tx Gas Limit")
        public BigInteger gasLimit = BigInteger.valueOf(100_000);
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
            for (String i : app.inputFile) {
                StreamFiles sf = new StreamFiles(i);
                while (sf.hasMore()) {
                    String next = sf.next();
                    try {
                        processCert(app, context, next);
                    } catch (Exception e) {
                        System.err.println(app.inputFile + ": " + Exceptions.getSmartExceptionMessage(e));
                    }
                }
            }

        }
    }


    private static void processCert(Args app, Context context, String f) {

        byte[] data = CliUtil.readData("CERTIFICATE", f);
        if (data == null) {
            log("error", "cannot load certificate from " + f);
            return;
        }
        DCRLUtils.DCRLContracts contracts = DCRLUtils.extractContracts(context, data);
        if (contracts == null) {
            return;
        }
        log("skid", KeyDumper.toHex(contracts.skid));

        for (String contractURI : contracts.contractAddress) {
            if (contractURI == null || !contractURI.startsWith(DCRL_ETHEREUM)) {
                log("warn", "unsupported smart contract " + contractURI);
            } else {
                String contractAdddress = contractURI.substring(DCRL_ETHEREUM.length());
                Web3j web3 = Web3j.build(new HttpService(app.httpService != null ? app.httpService : "http://localhost:8545/"));
                Credentials credentials;
                try {
                    credentials = WalletUtils.loadCredentials(app.wpass != null ? app.wpass : "", app.wsource);
                } catch (Exception e) {
                    log("error", "credentials: " + Exceptions.getSmartExceptionMessage(e));
                    return;
                }
                BigInteger price = app.gasPrice;

                if (price == BigInteger.valueOf(-1)) {
                    try {
                        price = web3.ethGasPrice().send().getGasPrice();
                    } catch (IOException e) {
                        log("error", "gas price: " + Exceptions.getSmartExceptionMessage(e));
                        return;
                    }

                    log("gas_estimated_price", price);

                }
                DCRL contract = DCRL.load(contractAdddress, web3, credentials, new StaticGasProvider(price, app.gasLimit));
                try {
                    TransactionReceipt tx = contract.revoke(new BigInteger(1, contracts.skid)).send();
                    log("status", tx.getStatus());
                    log("from", tx.getFrom());
                    log("to", tx.getTo());
                    log("contract_address", tx.getContractAddress());

                    log("hash", tx.getBlockHash());
                    log("number", tx.getBlockNumber());

                    log("used", tx.getGasUsed());
                    log("cumulative", tx.getCumulativeGasUsed());
                    log("revert_reason", tx.getRevertReason());
                    log("root", tx.getRoot());

                    log("hash", tx.getTransactionHash());
                    log("index", tx.getTransactionIndex());

                    log("revoked", "true");
                } catch (Exception e) {
                    log("error", "smartc entry call: " + Exceptions.getSmartExceptionMessage(e));
                }
            }
        }
        return;


    }

    private static void log(String key, Object value) {
        System.out.println(key + ": " + value);
    }


}