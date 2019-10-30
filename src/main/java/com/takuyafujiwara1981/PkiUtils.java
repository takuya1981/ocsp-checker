package com.takuyafujiwara1981;

import sun.security.x509.AccessDescription;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.URIName;
import sun.security.x509.X509CertImpl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

import static sun.security.x509.AccessDescription.Ad_CAISSUERS_Id;

class PkiUtils {

    static X509Certificate createX509Certificate(String certPem) throws CertificateException {
        return toX509Certificate(createCertificate(certPem));
    }

    static X509Certificate createX509Certificate(InputStream in) throws CertificateException {
        return toX509Certificate(createCertificate(in));
    }

    static Certificate createCertificate(String certPem) throws CertificateException {
        ByteArrayInputStream bais = new ByteArrayInputStream(certPem.getBytes());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(bais);
        return certificate;
    }

    static Certificate createCertificate(InputStream in) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Certificate certificate = certificateFactory.generateCertificate(in);
        return certificate;
    }

    static List<Certificate> createCertificates(String pkcs7Pem) throws CertificateException {
        List<Certificate> list = new ArrayList<>();
        ByteArrayInputStream bais = new ByteArrayInputStream(pkcs7Pem.getBytes());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        Collection c = certificateFactory.generateCertificates(bais);
        Iterator i = c.iterator();
        while (i.hasNext()) {
            list.add((Certificate)i.next());
        }
        return list;
    }

    static X509Certificate toX509Certificate(Certificate cert) {
        return (X509Certificate)cert;
    }

    static X509Certificate fetchIssuerCert(X509Certificate cert) throws CertificateException, IOException {
        X509CertImpl certImpl = X509CertImpl.toImpl(cert);
        AuthorityInfoAccessExtension extension = certImpl.getAuthorityInfoAccessExtension();

        Optional<AccessDescription> description = extension.getAccessDescriptions().stream()
                .filter(d -> d.getAccessMethod().equals((Object)Ad_CAISSUERS_Id))
                .findFirst();

        if (description.isPresent()) {
            URL url = ((URIName)(description.get().getAccessLocation().getName())).getURI().toURL();
            HttpURLConnection con = (HttpURLConnection)url.openConnection();
            con.setRequestMethod("GET");
            con.connect();

            final int status = con.getResponseCode();
            if (status == HttpURLConnection.HTTP_OK) {
                return createX509Certificate(con.getInputStream());
            } else {
                throw new IllegalArgumentException("HTTP status code is not 200. code:" + status);
            }
        }

        throw new IllegalArgumentException("Certification Authority Issuer was not exist.");
    }
}
