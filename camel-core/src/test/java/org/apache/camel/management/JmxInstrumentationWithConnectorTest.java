/**
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.camel.management;

import java.rmi.ConnectException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.util.Locale;
import java.util.Random;

import org.apache.camel.impl.DefaultCamelContext;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * CVE-2020-11971 backpatch: the JMX RMI connector path has been removed
 * unconditionally. Originally this class verified that a remote client could
 * connect to the Camel-opened RMI listener; that test no longer makes sense
 * because the listener is never opened. The class is retained (rather than
 * deleted) so re-runs of historical CI configurations still find a class by
 * this name, and the inverted expectation here documents the security
 * regression guard at the same code site.
 */
public class JmxInstrumentationWithConnectorTest extends Assert {

    private int registryPort;
    private DefaultCamelContext context;

    protected boolean canRunOnThisPlatform() {
        String os = System.getProperty("os.name");
        boolean aix = os.toLowerCase(Locale.ENGLISH).contains("aix");
        boolean windows = os.toLowerCase(Locale.ENGLISH).contains("windows");
        boolean solaris = os.toLowerCase(Locale.ENGLISH).contains("sunos");
        return !aix && !solaris && !windows;
    }

    @Before
    public void setUp() throws Exception {
        if (!canRunOnThisPlatform()) {
            return;
        }
        registryPort = 30000 + new Random().nextInt(10000);

        // request the legacy "open an RMI connector" path explicitly
        System.setProperty(JmxSystemPropertyKeys.USE_PLATFORM_MBS, "false");
        System.setProperty(JmxSystemPropertyKeys.CREATE_CONNECTOR, "true");
        System.setProperty(JmxSystemPropertyKeys.REGISTRY_PORT, "" + registryPort);

        context = new DefaultCamelContext();
        context.setName("camel-jmx-rebind-guard");
        context.getManagementStrategy(); // force JMX enabled init
        context.start();
    }

    @After
    public void tearDown() throws Exception {
        if (context != null) {
            context.stop();
            context = null;
        }
        System.clearProperty(JmxSystemPropertyKeys.USE_PLATFORM_MBS);
        System.clearProperty(JmxSystemPropertyKeys.DOMAIN);
        System.clearProperty(JmxSystemPropertyKeys.MBEAN_DOMAIN);
        System.clearProperty(JmxSystemPropertyKeys.CREATE_CONNECTOR);
        System.clearProperty(JmxSystemPropertyKeys.REGISTRY_PORT);
    }

    /**
     * Even with {@code createConnector=true} and a {@code registryPort}
     * configured, the backpatch must NOT bind a JMX RMI registry. A client
     * attempting to list the registry should hit a connection-level
     * failure (the port is unbound).
     */
    @Test
    public void testNoRmiRegistryIsOpenedEvenWithCreateConnectorTrue() throws Exception {
        if (!canRunOnThisPlatform()) {
            return;
        }
        Registry registry = LocateRegistry.getRegistry("localhost", registryPort);
        try {
            registry.list();
            fail("expected ConnectException — CVE-2020-11971 backpatch must not open an RMI registry");
        } catch (ConnectException expected) {
            // ok: nothing listening on the configured port
        } catch (RemoteException expected) {
            // ok: also acceptable — registry stub call surfaced a generic
            // remote failure rather than a typed ConnectException
        }
    }
}
