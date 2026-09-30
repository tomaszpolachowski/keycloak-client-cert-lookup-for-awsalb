# Keycloak X509 Client Certificate Lookup for AWS Application Load Balancer

This project provides an X509 client certificate lookup implementation for [AWS ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html).

> [!IMPORTANT]
> If mTLS in AWS ALB is enabled in **passthrough** mode, ensure to add trusted client CA certificates the the truststore in Keycloak to let this provider verify the certificate on its own. That's because AWS ALB never supplies full certificate chain to the target group, it must reconstruct it with own data.
> For more information, see [Configuring trusted certificates](https://www.keycloak.org/server/keycloak-truststore).
> 
> If mTLS in AWS ALB is enabled in **verify** mode, no further verification of the certificate chain is made by this provider.
> You must ensure to create a truststore in AWS ALB with appropriate trusted client CA certificates and associate it with listener for which the mTLS is enabled.
> For more information, see [Configuring mutual TLS on an Application Load Balancer](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/configuring-mtls-with-elb.html).

## Installation

This project is not available on Maven Central.
To compile it locally, ensure you have JDK, Git and Maven installed.
Clone the repository and execute:

```
mvn clean package
```

The JAR file will be created in the `target` directory.
Copy the JAR file to the `providers` directory in your Keycloak distribution.
For instance, in the official Keycloak Docker image releases, place the JAR file in the `/opt/keycloak/providers/`.

A pre-built JAR file is also available at [`https://github.com/tomaszpolachowski/keycloak-client-cert-lookup-for-awsalb/releases/latest`](https://github.com/tomaszpolachowski/keycloak-client-cert-lookup-for-awsalb/releases/latest).

### Enable client certificate lookup (mandatory)

Add the following command line parameter to `kc.sh` to choose the provider:

```
--spi-x509cert-lookup-provider=awsalb
```

Alternatively, you can set the environment variable `KC_SPI_X509CERT_LOOKUP_PROVIDER=awsalb` or specify `spi-x509cert-lookup-provider=awsalb` in the Keycloak configuration file.

Restart Keycloak for the changes to take effect.
You will see a warning in the logs when the JAR file is loaded:

Refer to Keycloak's [Configuring Providers](https://www.keycloak.org/server/configuration-provider) documentation for more information.


### Authorizing clients that are allowed to send headers with certificates (optional)

If Keycloak is deployed in an environment where some clients must bypass the load balancer, it is important to ensure that only AWS ALB can send headers with certificates. This prevents clients from impersonating other users by manipulating the headers.

Following headers are assumed to always come from AWS ALB:
* `X-Amzn-Mtls-Clientcert` in **passthrough** mode
* `X-Amzn-Mtls-Clientcert-Leaf` in **verify** mode
