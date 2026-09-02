/*
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
package org.apache.camel.component.knative.http;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CVE-2026-47323: a Knative HTTP endpoint accepted Camel-internal headers from the wire, so a request
 * header named after a header-driven component's option (CamelExecCommandExecutable,
 * CamelFileName) overrode the route's configured value.
 */
public class KnativeHttpHeaderFilterStrategyInboundTest {

    private final KnativeHttpHeaderFilterStrategy strategy = new KnativeHttpHeaderFilterStrategy();

    @Test
    public void filtersCamelInternalHeadersArrivingFromTheWire() {
        assertTrue(strategy.applyFilterToExternalHeaders("CamelExecCommandExecutable", "/bin/sh", null));
        assertTrue(strategy.applyFilterToExternalHeaders("CamelFileName", "../../etc/passwd", null));
        assertTrue(strategy.applyFilterToExternalHeaders("camelFileName", "../../etc/passwd", null));
        assertTrue(strategy.applyFilterToExternalHeaders("org.apache.camel.internal", "x", null));
    }

    @Test
    public void keepsOrdinaryInboundHeaders() {
        assertFalse(strategy.applyFilterToExternalHeaders("Accept", "application/json", null));
        assertFalse(strategy.applyFilterToExternalHeaders("X-Correlation-Id", "42", null));
    }
}
