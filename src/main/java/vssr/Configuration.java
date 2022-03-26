package vssr;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

public class Configuration {
    private static String configurationFilePath = "config" + File.separator + "vssr.config";
    private String vssScheme;
    private String primeField;
    private String subPrimeField;
    private String generator;
    private String dataEncryptionAlgorithm;
    private String shareEncryptionAlgorithm;
    private int recoveryPort;
    private boolean useTLSEncryption;
    private int shareProcessingThreads;
    private boolean verifyClientRequests;
    private static Configuration INSTANT;
    
    public static void setConfigurationFilePath(final String configurationFilePath) {
        Configuration.configurationFilePath = configurationFilePath;
    }
    
    public static Configuration getInstance() {
        if (Configuration.INSTANT == null) {
            try {
                Configuration.INSTANT = new Configuration(Configuration.configurationFilePath);
            }
            catch (IOException e) {
                e.printStackTrace();
            }
        }
        return Configuration.INSTANT;
    }
    
    private Configuration(final String configurationFilePath) throws IOException {
        dataEncryptionAlgorithm = "AES";
        shareEncryptionAlgorithm = "AES";
        try (BufferedReader in = new BufferedReader(new FileReader(configurationFilePath))) {
            String line;
            while ((line = in.readLine()) != null) {
                if (line.startsWith("#")) {
                    continue;
                }
                String[] tokens = line.split("=");
                if (tokens.length != 2) {
                    continue;
                }
                String propertyName = tokens[0].trim();
                String value = tokens[1].trim();
                switch (propertyName) {
                    case "cobra.vss.scheme": {
                        if (value.equals("linear")) {
                            vssScheme = "1";
                            continue;
                        }
                        if (value.equals("constant")) {
                            vssScheme = "2";
                            continue;
                        }
                        throw new IllegalArgumentException("Property cobra.vss.scheme has invalid value");
                    }
                    case "cobra.vss.prime_field": {
                        primeField = value;
                        continue;
                    }
                    case "cobra.vss.sub_field": {
                        subPrimeField = value;
                        continue;
                    }
                    case "cobra.vss.generator": {
                        generator = value;
                        continue;
                    }
                    case "cobra.vss.data_encryption_algorithm": {
                        dataEncryptionAlgorithm = value;
                        continue;
                    }
                    case "cobra.vss.share_encryption_algorithm": {
                        shareEncryptionAlgorithm = value;
                        continue;
                    }
                    case "cobra.recovery.port": {
                        recoveryPort = Integer.parseInt(value);
                        continue;
                    }
                    case "cobra.communication.use_tls_encryption": {
                        useTLSEncryption = Boolean.parseBoolean(value);
                        continue;
                    }
                    case "cobra.share_processing_threads": {
                        shareProcessingThreads = Integer.parseInt(value);
                        continue;
                    }
                    case "cobra.verify.requests": {
                        verifyClientRequests = Boolean.parseBoolean(value);
                        continue;
                    }
                    default: {
                        throw new IllegalArgumentException("Unknown property name");
                    }
                }
            }
        }
    }
    
    public int getShareProcessingThreads() {
        return this.shareProcessingThreads;
    }
    
    public boolean isVerifyClientRequests() {
        return this.verifyClientRequests;
    }
    
    public String getVssScheme() {
        return this.vssScheme;
    }
    
    public String getPrimeField() {
        return this.primeField;
    }
    
    public String getSubPrimeField() {
        return this.subPrimeField;
    }
    
    public String getGenerator() {
        return this.generator;
    }
    
    public String getDataEncryptionAlgorithm() {
        return this.dataEncryptionAlgorithm;
    }
    
    public String getShareEncryptionAlgorithm() {
        return this.shareEncryptionAlgorithm;
    }
    
    public int getRecoveryPort() {
        return this.recoveryPort;
    }
    
    public boolean useTLSEncryption() {
        return this.useTLSEncryption;
    }
}
