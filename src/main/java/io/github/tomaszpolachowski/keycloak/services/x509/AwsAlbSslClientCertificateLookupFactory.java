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
import org.keycloak.services.x509.X509ClientCertificateLookupFactory;
import org.keycloak.services.x509.X509ClientCertificateLookup;

import org.jboss.logging.Logger;


public class AwsAlbSslClientCertificateLookupFactory implements X509ClientCertificateLookupFactory {
    private static final Logger logger = Logger.getLogger(AwsAlbSslClientCertificateLookupFactory.class);
    private static final String PROVIDER = "awsalb";
    private volatile boolean isTruststoreLoaded;
    private Set<X509Certificate> trustedRootCerts;
    private Set<X509Certificate> intermediateCerts;

    private final static String CERTIFICATE_CHAIN_LENGTH = "certificateChainLength";
    private int certificateChainLength = 1;

    @Override
    public void init(Config.Scope config) {
        this.isTruststoreLoaded = false;
        this.trustedRootCerts = ConcurrentHashMap.newKeySet();
        this.intermediateCerts = ConcurrentHashMap.newKeySet();
        certificateChainLength = config.getInt(CERTIFICATE_CHAIN_LENGTH, 1);
        logger.tracev("{0}: ''{1}''", CERTIFICATE_CHAIN_LENGTH, certificateChainLength);
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public X509ClientCertificateLookup create(KeycloakSession session) {
        loadKeycloakTrustStore(session);
        return new AwsAlbSslClientCertificateLookup(intermediateCerts, trustedRootCerts, isTruststoreLoaded, certificateChainLength);
    }

    @Override
    public String getId() {
        return PROVIDER;
    }

    /**  Loading truststore @ first login
     *
     * @param session keycloak session
     */
    private void loadKeycloakTrustStore(KeycloakSession session) {

        if (isTruststoreLoaded){
            return;
        }

        synchronized (this) {
            if (isTruststoreLoaded) {
                return;
            }
            logger.debug(" Loading Keycloak truststore ...");
            KeycloakSessionFactory factory = session.getKeycloakSessionFactory();
            TruststoreProviderFactory truststoreFactory = (TruststoreProviderFactory) factory.getProviderFactory(TruststoreProvider.class);
            TruststoreProvider provider = truststoreFactory.create(session);

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
