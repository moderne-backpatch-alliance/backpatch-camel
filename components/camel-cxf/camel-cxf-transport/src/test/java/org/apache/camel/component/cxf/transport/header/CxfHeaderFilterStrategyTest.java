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
package org.apache.camel.component.cxf.transport.header;

import org.apache.camel.spi.HeaderFilterStrategy;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CxfHeaderFilterStrategyTest {

    @Test
    public void testFilterInboundCamelHeaders() {
        HeaderFilterStrategy filter = new CxfHeaderFilterStrategy();
        assertTrue(filter.applyFilterToExternalHeaders("CamelFoo", "just a test", null));
        assertTrue(filter.applyFilterToExternalHeaders("camelfoo", "just a test", null));
        assertTrue(filter.applyFilterToExternalHeaders("org.apache.camel.Foo", "just a test", null));

        assertFalse(filter.applyFilterToExternalHeaders("MyWorld", "just a test", null));
    }

    @Test
    public void testFilterOutboundCamelHeaders() {
        HeaderFilterStrategy filter = new CxfHeaderFilterStrategy();
        assertTrue(filter.applyFilterToCamelHeaders("CamelFoo", "just a test", null));
        assertFalse(filter.applyFilterToCamelHeaders("MyWorld", "just a test", null));
    }
}
