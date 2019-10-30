package com.takuyafujiwara1981;

import sun.security.provider.certpath.OCSP;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;


public class OcspChecker {
    public static void main(String[] args) {

        if (args.length < 1 || 2 < args.length) {
            showUsage();
            return;
        }

        try {
            X509Certificate cert = (PkiUtils.createX509Certificate(readFileAsString(args[0])));
            X509Certificate issuerCert = args.length == 1 ?
                    PkiUtils.fetchIssuerCert(cert) :
                    PkiUtils.createX509Certificate(readFileAsString(args[1]));

            URI uri = OCSP.getResponderURI(cert);
            OCSP.RevocationStatus revocationStatus = OCSP.check(cert, issuerCert, uri, null, null);

            System.out.println("OCSP Certificate Status: " + revocationStatus.getCertStatus().toString());
            if (OCSP.RevocationStatus.CertStatus.REVOKED.equals(revocationStatus.getCertStatus())) {
                final String template = "Revocation reason: %s, Revocation time: %s";
                System.out.println(String.format(template, revocationStatus.getRevocationReason().toString(),
                        revocationStatus.getRevocationTime().toString()));
            }
        } catch(Exception ex) {
            ex.printStackTrace();
        }
    }

    private static String readFileAsString(final String path) throws IOException {
        return (new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8))
                .replace("\uFEFF", "");
    }

    private static void showUsage() {
        System.out.println("Usage: ocsp-checker cert_pem_file_path [issuer_pem_file_path]");
        System.out.println("  issuer_pem_file_path: If not specify, This tool try to get issuer cert from URL of Certificate Authority Issuers(1.3.6.1.5.5.7.48.2) in cert pem.");
    }
}
