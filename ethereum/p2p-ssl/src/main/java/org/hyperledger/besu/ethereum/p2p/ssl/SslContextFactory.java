/*
 * Copyright ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package org.hyperledger.besu.ethereum.p2p.ssl;

import org.hyperledger.besu.ethereum.p2p.ssl.config.SSLConfiguration;
import org.hyperledger.besu.ethereum.p2p.ssl.keystore.HardwareKeyStoreWrapper;
import org.hyperledger.besu.ethereum.p2p.ssl.keystore.KeyStoreWrapper;
import org.hyperledger.besu.ethereum.p2p.ssl.keystore.SoftwareKeyStoreWrapper;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.IdentityCipherSuiteFilter;
import io.netty.handler.ssl.JdkSslContext;
import io.netty.handler.ssl.SslContext;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class SslContextFactory {

  private static final Logger LOG = LogManager.getLogger();

  private static final String[] ALLOWED_PROTOCOLS = {"TLSv1.3"};
  private static final String KEYMANAGER_FACTORY_ALGORITHM = "PKIX";
  private static final String TRUSTMANAGER_FACTORY_ALGORITHM = "PKIX";
  private static List<String> enabledCipherSuites =
      null; // cache enabled cipher suites for chosen (most recent)
  // allowed protocol

  private KeyManagerFactory kmf;
  private TrustManagerFactory tmf;
  private Collection<X509CRL> crls;

  protected SslContextFactory() {}

  protected SslContextFactory(
      final String keystorePass,
      final KeyStoreWrapper keystoreWrapper,
      final String serverKeyAlias,
      final String clientKeyAlias)
      throws GeneralSecurityException, IOException {
    kmf = getKeyManagerFactory(keystoreWrapper.getKeyStore(), keystorePass);
    tmf = getTrustManagerFactory(keystoreWrapper.getTrustStore());
    crls = keystoreWrapper.getCRLs();
  }

  public static SslContextFactory getInstance(
      final String keystorePass,
      final KeyStoreWrapper keystoreWrapper,
      final String serverKeyAlias,
      final String clientKeyAlias,
      final List<String> configuredCipherSuites)
      throws GeneralSecurityException, IOException {

    configureEnabledCiphers(configuredCipherSuites);

    LOG.debug(
        "Creating instance serverKeyAlias:{}, clientKeyAlias:{}, enabledCipherSuites: {}",
        serverKeyAlias,
        clientKeyAlias,
        enabledCipherSuites);

    return new SslContextFactory(keystorePass, keystoreWrapper, serverKeyAlias, clientKeyAlias);
  }

  /**
   * If a list of ciphers is given in config files, enable only these (else the default cipher suite
   * will be enabled).
   *
   * @param configuredCipherSuites a list of enabled ciphers
   */
  private static void configureEnabledCiphers(final List<String> configuredCipherSuites) {
    if (configuredCipherSuites != null && !configuredCipherSuites.isEmpty()) {
      enabledCipherSuites = configuredCipherSuites;
    }
  }

  /**
   * Creates and returns a Netty specific SslContext to be used in a Netty's server. The SslContext
   * is configured to require client authentication (Mutual Authenticated SSL/TLS), only support a
   * specific list of protocols (currently "TLSv1.2") and is backed by a Java Keystore or PKCS#11
   * Keystore, depending on how the factory was initialised.
   *
   * @return Netty specific server SslContext
   * @throws NoSuchAlgorithmException Throws NoSuchAlgorithmException
   * @throws KeyManagementException Throws KeyManagementException
   */
  public SslContext createNettyServerSslContext()
      throws NoSuchAlgorithmException, KeyManagementException {
    final List<String> enabledCipherSuites = getEnabledCipherSuites();

    return new JdkSslContext(
        createJavaSslContext(),
        false,
        enabledCipherSuites,
        IdentityCipherSuiteFilter.INSTANCE,
        null,
        ClientAuth.REQUIRE,
        null,
        false);
  }

  /**
   * Creates and returns a Netty specific SslContext to be used in a Netty's client. The SslContext
   * is configured to only support a specific list of protocols (currently "TLSv1.2") and is backed
   * by a Java Keystore or PKCS#11 Keystore, depending on how the factory was initialised.
   *
   * @return Netty specific client SslContext
   * @throws NoSuchAlgorithmException Throws NoSuchAlgorithmException
   * @throws KeyManagementException Throws KeyManagementException
   */
  public SslContext createNettyClientSslContext()
      throws NoSuchAlgorithmException, KeyManagementException {
    final List<String> enabledCipherSuites = getEnabledCipherSuites();

    return new JdkSslContext(
        createJavaSslContext(),
        true,
        enabledCipherSuites,
        IdentityCipherSuiteFilter.INSTANCE,
        null,
        ClientAuth.NONE,
        null,
        false);
  }

  /**
   * Creates and returns a Java (JCA) SslContext to be used generically by clients. The SslContext
   * is configured to only support a specific list of protocols (currently "TLSv1.3") and is backed
   * by a Java Keystore or PKCS#11 Keystore, depending on how the factory was initialised.
   *
   * @return Java SslContext
   * @throws NoSuchAlgorithmException Throws NoSuchAlgorithmException
   * @throws KeyManagementException Throws KeyManagementException
   */
  public SSLContext createJavaSslContext() throws NoSuchAlgorithmException, KeyManagementException {
    final SSLContext context = SSLContext.getInstance(getTlsProtocol());
    context.init(
        kmf.getKeyManagers(),
        null == crls || crls.isEmpty() ? tmf.getTrustManagers() : wrap(tmf.getTrustManagers()),
        null);
    return context;
  }

  protected TrustManager[] wrap(final TrustManager[] trustMgrs) {
    final TrustManager[] ret = trustMgrs.clone();
    for (int i = 0; i < ret.length; i++) {
      TrustManager trustMgr = ret[i];
      if (trustMgr instanceof X509TrustManager) {
        X509TrustManager x509TrustManager = (X509TrustManager) trustMgr;
        ret[i] =
            new X509TrustManager() {
              @Override
              public void checkClientTrusted(
                  final X509Certificate[] x509Certificates, final String s)
                  throws CertificateException {
                checkRevoked(x509Certificates);
                x509TrustManager.checkClientTrusted(x509Certificates, s);
              }

              @Override
              public void checkServerTrusted(
                  final X509Certificate[] x509Certificates, final String s)
                  throws CertificateException {
                checkRevoked(x509Certificates);
                x509TrustManager.checkServerTrusted(x509Certificates, s);
              }

              private void checkRevoked(final X509Certificate[] x509Certificates)
                  throws CertificateException {
                for (X509CRL crl : crls) {
                  for (X509Certificate cert : x509Certificates) {
                    if (crl.isRevoked(cert)) {
                      throw new CertificateException("Certificate revoked");
                    }
                  }
                }
              }

              @Override
              public X509Certificate[] getAcceptedIssuers() {
                return x509TrustManager.getAcceptedIssuers();
              }
            };
      }
    }
    return ret;
  }

  protected TrustManagerFactory getTrustManagerFactory(final KeyStore truststore)
      throws GeneralSecurityException {
    final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TRUSTMANAGER_FACTORY_ALGORITHM);
    tmf.init(truststore);
    return tmf;
  }

  protected KeyManagerFactory getKeyManagerFactory(
      final KeyStore keystore, final String keystorePassword) throws GeneralSecurityException {
    final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KEYMANAGER_FACTORY_ALGORITHM);
    kmf.init(keystore, keystorePassword.toCharArray());
    return kmf;
  }

  /**
   * The list of default (enabled) ciphers configured in Netty is very restrictive. So, instead, we
   * are using whatever ciphers are configured/enabled on the JDK for the most recent SSL/TLS
   * protocol configured on this class.
   *
   * <p>Without this, connections with other nodes (Erlang or Java) will fail the TLS handshake with
   * the message: "no cipher suites in common" This only happens when using EC keys / ECDSA
   * certificates.
   *
   * <p>For the list of Netty's default cipher suites, see <a href=
   * "https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility">
   * https://wiki.mozilla.org/Security/Server_Side_TLS#Modern_compatibility</a>
   *
   * <p>See also:
   *
   * <blockquote>
   *
   * <code>
   * <p>io.netty.handler.ssl.SslUtils#DEFAULT_CIPHER_SUITES
   * <p>io.netty.handler.ssl.JdkSslContext
   * </code>
   *
   * </blockquote>
   *
   * @return list of enabled cipher suites
   * @see SslContextFactory#ALLOWED_PROTOCOLS
   */
  private static List<String> getEnabledCipherSuites() {
    final String protocol = getTlsProtocol();
    try {
      if (enabledCipherSuites == null || enabledCipherSuites.isEmpty()) {
        final SSLContext sslcontext = SSLContext.getInstance(protocol);
        sslcontext.init(null, null, null);
        enabledCipherSuites = Arrays.asList(sslcontext.createSSLEngine().getEnabledCipherSuites());
      }
    } catch (final Exception e) {
      LOG.warn(
          "Could not get list of enabled (JDK) cipher suites for protocol:{}, reverting to Netty's default ones.",
          protocol);
    }
    return enabledCipherSuites;
  }

  private static String getTlsProtocol() {
    // pick the highest SSL/TLS protocol identifier allowed
    return Arrays.stream(ALLOWED_PROTOCOLS).max(Comparator.naturalOrder()).orElse(null);
  }

  public static SslContextFactory buildFrom(final SSLConfiguration config)
      throws GeneralSecurityException, IOException {
    SslContextFactory ret = null;
    if (null != config) {
      LOG.info("Initializing SSL Context using {} keystore.", config.getKeyStoreType());
      KeyStoreWrapper wrapper =
          KeyStoreWrapper.KEYSTORE_TYPE_PKCS11.equalsIgnoreCase(config.getKeyStoreType())
              ? new HardwareKeyStoreWrapper(
                  config.getKeyStorePassword(), config.getKeyStorePath(), config.getCrlPath())
              : new SoftwareKeyStoreWrapper(
                  config.getKeyStoreType(),
                  config.getKeyStorePath(),
                  config.getKeyStorePassword(),
                  config.getTrustStoreType(),
                  config.getTrustStorePath(),
                  config.getTrustStorePassword(),
                  config.getCrlPath());
      ret = SslContextFactory.getInstance(config.getKeyStorePassword(), wrapper, null, null, null);
    }
    return ret;
  }
}
