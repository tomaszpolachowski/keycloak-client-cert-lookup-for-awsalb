package io.github.tomaszpolachowski.keycloak.services.x509;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import org.keycloak.common.util.PemException;
import org.keycloak.common.util.PemUtils;
import org.keycloak.http.HttpRequest;
import org.keycloak.services.x509.AbstractClientCertificateFromHttpHeadersLookup;

import org.jboss.logging.Logger;


public class AwsAlbTrustedClientCertificateLookup extends AbstractClientCertificateFromHttpHeadersLookup {

    private static final Logger log = Logger.getLogger(AwsAlbTrustedClientCertificateLookup.class);

    public AwsAlbTrustedClientCertificateLookup(int certificateChainLength) {
        super("X-Amzn-Mtls-Clientcert-Leaf", "", certificateChainLength);
    }

    @Override
    protected X509Certificate getCertificateFromHttpHeader(HttpRequest request, String httpHeader) throws GeneralSecurityException {
        X509Certificate certificate = super.getCertificateFromHttpHeader(request, httpHeader);
        if (certificate == null) {
            return null;
        }
        String validCertificateResult = request.getHttpHeaders().getRequestHeaders().getFirst("X-Amzn-Mtls-Clientcert-Issuer");
        if (validCertificateResult != null || !validCertificateResult.isEmpty()) {
            return certificate;
        } else {
            log.warn("could not verify the certificate: X-Amzn-Mtls-Clientcert-Issuer is empty");
            return null;
        }
    }

    @Override
    protected X509Certificate decodeCertificateFromPem(String pem) throws PemException {

        if (pem == null) {
            log.warn("End user TLS Certificate is NULL! ");
            return null;
        }

        /* AWS always URL-encodes the client certificate but treats + character as safe while it's commonly used to indicate space */
        /* To avoid it to be interpreted as space, URL-encode it too */
        pem = java.net.URLDecoder.decode(pem.replaceAll("+", "%2B"), StandardCharsets.UTF_8);

        return PemUtils.decodeCertificate(pem);
    }

}
