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

import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.ConnectException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.spi.ManagementAgent;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

/**
 * Regression test for CVE-2020-11971 (Apache Camel JMX Rebind Flaw).
 *
 * <p>Camel 2.x exposed an unauthenticated JMX RMI listener when the
 * management agent was configured with {@code createConnector=true}. An
 * attacker on a reachable network could bind a malicious MBean over the
 * RMI registry — the so-called "JMX rebind" attack. Upstream removed the
 * feature entirely in 3.2.0 (CAMEL-14811). This backpatch ports that
 * intent to 2.25.4 by making
 * {@code DefaultManagementAgent#createJmxConnector} a no-op and never
 * invoking it from {@code createMBeanServer()}.
 *
 * <p>The tests below cover the two surfaces a 2.x consumer would use to
 * request the legacy connector:
 *
 * <ol>
 *   <li>System property {@code org.apache.camel.jmx.createRmiConnector=true}
 *       (the JVM-wide opt-in path used by stand-alone runs).</li>
 *   <li>Programmatic {@code ManagementAgent#setCreateConnector(true)}
 *       (the Spring XML / Karaf blueprint configuration path).</li>
 * </ol>
 *
 * <p>Both paths must leave the RMI registry port unbound. We assert this
 * by attempting to lookup any name in the configured registry and
 * expecting a {@link ConnectException} (or generic {@link RemoteException})
 * — the failure mode you get when nothing is listening on the port.
 *
 * <p>The registry port is chosen by allocating an ephemeral port, closing
 * it, and reusing the number — modelled on the
 * {@code JmxInstrumentationWithConnectorTest} pattern. This avoids
 * collisions with whatever other JMX listeners may be active on the test
 * host.
 */
public class JmxRebindGuardSecurityTest extends Assert {

    private int registryPort;
    private DefaultCamelContext context;

    private static int allocateFreePort() throws IOException {
        ServerSocket s = new ServerSocket(0);
        try {
            return s.getLocalPort();
        } finally {
            s.close();
        }
    }

    @Before
    public void allocatePort() throws Exception {
        registryPort = allocateFreePort();
    }

    @After
    public void cleanup() throws Exception {
        if (context != null) {
            try {
                context.stop();
            } catch (Exception ignored) {
                // best-effort
            }
            context = null;
        }
        System.clearProperty(JmxSystemPropertyKeys.USE_PLATFORM_MBS);
        System.clearProperty(JmxSystemPropertyKeys.CREATE_CONNECTOR);
        System.clearProperty(JmxSystemPropertyKeys.REGISTRY_PORT);
    }

    /**
     * The classic 2.x "open a JMX RMI listener" recipe via system
     * properties. After the backpatch this must not bind a registry.
     */
    @Test
    public void createConnectorTrueDoesNotOpenRmiPort() throws Exception {
        System.setProperty(JmxSystemPropertyKeys.USE_PLATFORM_MBS, "false");
        System.setProperty(JmxSystemPropertyKeys.CREATE_CONNECTOR, "true");
        System.setProperty(JmxSystemPropertyKeys.REGISTRY_PORT, Integer.toString(registryPort));

        context = new DefaultCamelContext();
        context.setName("camel-jmx-rebind-guard-syspropath");
        context.start();

        assertNoRmiRegistryBound(registryPort);
    }

    /**
     * The Spring XML / blueprint XML programmatic recipe — call
     * {@code setCreateConnector(true)} on the management agent. After the
     * backpatch this must not bind a registry. The setter signature itself
     * remains for binary compatibility but the value is never used to open
     * an RMI listener.
     */
    @Test
    public void setCreateConnectorProgrammaticallyDoesNotOpenRmiPort() throws Exception {
        context = new DefaultCamelContext();
        context.setName("camel-jmx-rebind-guard-programmatic");
        // JMX management is on by default in 2.x unless disableJMX() is called.
        ManagementAgent agent = context.getManagementStrategy().getManagementAgent();
        if (agent != null) {
            agent.setCreateConnector(true);
            agent.setRegistryPort(registryPort);
            agent.setConnectorPort(registryPort);
            agent.setServiceUrlPath("/jmxrmi/camel");
        }
        context.start();

        assertNoRmiRegistryBound(registryPort);
    }

    /**
     * Sanity guard: the setters in question must continue to exist with
     * their original signatures. If a future refactor accidentally removes
     * or renames them, this test catches the binary-compat regression
     * before consumer XML configs break at class-load time.
     */
    @Test
    public void deprecatedSettersRetainBinaryCompatSignatures() throws Exception {
        Class<?> iface = ManagementAgent.class;
        // Method signatures: declared on the SPI interface, returning void.
        iface.getMethod("setCreateConnector", Boolean.class);
        iface.getMethod("setRegistryPort", Integer.class);
        iface.getMethod("setConnectorPort", Integer.class);
        iface.getMethod("setServiceUrlPath", String.class);
    }

    private static void assertNoRmiRegistryBound(int port) throws Exception {
        Registry registry = LocateRegistry.getRegistry("localhost", port);
        try {
            // list() is the cheapest "is anything bound here?" probe. It
            // performs an actual RMI roundtrip; a healthy registry would
            // return a (possibly empty) array of bound names. After the
            // backpatch nothing is listening, so the call must throw.
            String[] bound = registry.list();
            fail("CVE-2020-11971 regression: Registry.list() at localhost:" + port
                    + " returned " + bound.length + " bound names — an RMI registry was opened");
        } catch (ConnectException expected) {
            // ok: the port is unbound
        } catch (RemoteException expected) {
            // ok: any other RMI-layer failure is also a pass — what we
            // must NOT see is a successful list() against a Camel-opened
            // registry
        }
    }
}
