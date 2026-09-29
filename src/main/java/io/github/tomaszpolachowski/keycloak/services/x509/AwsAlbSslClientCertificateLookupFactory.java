package io.github.tomaszpolachowski.keycloak.services.x509;

import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.truststore.TruststoreProvider;
import org.keycloak.truststore.TruststoreProviderFactory;
import org.keycloak.services.x509.AbstractClientCertificateFromHttpHeadersLookupFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import org.jboss.logging.Logger;


public class AwsAlbSslClientCertificateLookupFactory extends AbstractClientCertificateFromHttpHeadersLookupFactory {

    private static final Logger logger = Logger.getLogger(AwsAlbSslClientCertificateLookupFactory.class);

    private static final String PROVIDER = "awsalb";

    protected static final String TRUST_ALB_VERIFICATION = "trust-alb-verification";

    protected boolean trustALBVerification;

    private volatile boolean isTruststoreLoaded;

    private Set<X509Certificate> trustedRootCerts;

    private Set<X509Certificate> intermediateCerts;

    @Override
    public void init(Config.Scope config) {
        super.init(config);
        this.trustALBVerification = config.getBoolean(TRUST_ALB_VERIFICATION, false);
        logger.tracev("{0}: ''{1}''", TRUST_ALB_VERIFICATION, trustALBVerification);
        this.isTruststoreLoaded = false;
        this.trustedRootCerts = ConcurrentHashMap.newKeySet();
        this.intermediateCerts = ConcurrentHashMap.newKeySet();

    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        loadKeycloakTrustStore(session);
        if (trustALBVerification) {
            return new AwsAlbTrustedClientCertificateLookup(certificateChainLength);
        } else {
            return new AwsAlbSslClientCertificateLookup(certificateChainLength, intermediateCerts, trustedRootCerts, isTruststoreLoaded);
        }
    }

    @Override
    public String getId() {
        return PROVIDER;
    }

    /**  Loading truststore @ first login
     *
     * @param kcSession keycloak session
     */
    private void loadKeycloakTrustStore(KeycloakSession kcSession) {

        if (isTruststoreLoaded){
            return;
        }

        synchronized (this) {
            if (isTruststoreLoaded) {
                return;
            }
            logger.debug(" Loading Keycloak truststore ...");
            KeycloakSessionFactory factory = kcSession.getKeycloakSessionFactory();
            TruststoreProviderFactory truststoreFactory = (TruststoreProviderFactory) factory.getProviderFactory(TruststoreProvider.class);
            TruststoreProvider provider = truststoreFactory.create(kcSession);

            if (provider != null && provider.getTruststore() != null) {
                Set<X509Certificate> rootCertificates = provider.getRootCertificates().entrySet().stream().flatMap(t -> t.getValue().stream()).collect(Collectors.toSet());
                Set<X509Certificate> intermediateCertficiates = provider.getIntermediateCertificates().entrySet().stream().flatMap(t -> t.getValue().stream()).collect(Collectors.toSet());

                trustedRootCerts.addAll(rootCertificates);
                intermediateCerts.addAll(intermediateCertficiates);
                logger.debug("Keycloak truststore loaded for NGINX x509cert-lookup provider.");

                isTruststoreLoaded = true;
            }
        }
    }
}
