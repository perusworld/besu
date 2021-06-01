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
package org.hyperledger.besu.ethereum.p2p.ssl.keystore;

import org.hyperledger.besu.ethereum.p2p.ssl.CryptoRuntimeException;

import java.nio.file.Path;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runners.Parameterized;

public class HardwareKeyStoreWrapperTest extends BaseKeyStoreWrapperTest {

  private static final String config = "/keys/partner1client1/partner1client1.cfg";
  private static final String configName = "NSScrypto-partner1client1";
  private static final String validKeystorePassword = "test123";

  @Parameterized.Parameters(name = "{index}: {0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {
          {
            "HardwareKeyStoreWrapper[PKCS11 keystore/truststore]",
            true,
            CryptoTestUtil.isNSSLibInstalled() ? getHardwareKeyStoreWrapper(configName) : null
          }
        });
  }

  private static KeyStoreWrapper getHardwareKeyStoreWrapper(final String cfgName) {
    try {
      final Path path = toPath(config);
      final Optional<Provider> existingProvider =
          Stream.of(Security.getProviders())
              .filter(p -> p.getName().equals("SunPKCS11" + cfgName))
              .findAny();
      return existingProvider
          .map(provider -> new HardwareKeyStoreWrapper(validKeystorePassword, provider))
          .orElseGet(() -> new HardwareKeyStoreWrapper(validKeystorePassword, path));
    } catch (final Exception e) {
      throw new CryptoRuntimeException("Failed to initialize NSS keystore", e);
    }
  }

  @Before
  public void beforeMethod() {
    Assume.assumeTrue(
        "Test ignored due to NSS library not being installed/detected.",
        CryptoTestUtil.isNSSLibInstalled());
  }

  @Test(expected = IllegalArgumentException.class)
  public void getPkcs11Provider() throws Exception {
    final HardwareKeyStoreWrapper sut =
        (HardwareKeyStoreWrapper) getHardwareKeyStoreWrapper(configName);
    sut.getPkcs11Provider("no-library");
  }

  @Test
  public void init_keystorePassword_config() throws Exception {
    new HardwareKeyStoreWrapper(validKeystorePassword, toPath(config));
  }

  @Test(expected = NullPointerException.class)
  public void init_keystorePassword_config_invalid() throws Exception {
    final String config = "invalid";
    new HardwareKeyStoreWrapper(validKeystorePassword, toPath(config));
  }

  @Test(expected = CryptoRuntimeException.class)
  public void init_keystorePassword_config_missing_pw() throws Exception {
    new HardwareKeyStoreWrapper(null, toPath(config));
  }

  @Test(expected = CryptoRuntimeException.class)
  public void init_keystorePassword_provider_missing_pw() throws Exception {
    final Provider p = null;
    new HardwareKeyStoreWrapper(validKeystorePassword, p);
  }
}