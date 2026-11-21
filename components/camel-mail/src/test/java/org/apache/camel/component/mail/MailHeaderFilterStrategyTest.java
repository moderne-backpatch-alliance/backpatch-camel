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
package org.apache.camel.component.mail;

import java.util.Map;

import javax.mail.Session;
import javax.mail.internet.MimeMessage;

import org.apache.camel.CamelContext;
import org.apache.camel.Exchange;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.support.DefaultExchange;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class MailHeaderFilterStrategyTest {

    private CamelContext context;

    @BeforeEach
    public void setUp() {
        context = new DefaultCamelContext();
        context.start();
    }

    @AfterEach
    public void tearDown() {
        context.stop();
    }

    @Test
    public void testInboundCamelHeaderIsFiltered() {
        MailHeaderFilterStrategy strategy = new MailHeaderFilterStrategy();
        Exchange exchange = new DefaultExchange(context);

        assertTrue(strategy.applyFilterToExternalHeaders("CamelFoo", "bar", exchange));
        assertTrue(strategy.applyFilterToExternalHeaders("camelFoo", "bar", exchange));
        assertTrue(strategy.applyFilterToExternalHeaders("org.apache.camel.Foo", "bar", exchange));
        assertFalse(strategy.applyFilterToExternalHeaders("Subject", "bar", exchange));
    }

    @Test
    public void testOutboundCamelHeaderIsStillFiltered() {
        MailHeaderFilterStrategy strategy = new MailHeaderFilterStrategy();
        Exchange exchange = new DefaultExchange(context);

        assertTrue(strategy.applyFilterToCamelHeaders("CamelFoo", "bar", exchange));
        assertFalse(strategy.applyFilterToCamelHeaders("Subject", "bar", exchange));
    }

    @Test
    public void testInboundCamelMailHeaderIsNotMappedToExchange() throws Exception {
        MailEndpoint endpoint = context.getEndpoint("pop3://localhost?username=james", MailEndpoint.class);
        Exchange exchange = endpoint.createExchange();

        MimeMessage message = new MimeMessage(Session.getInstance(System.getProperties()));
        message.setSubject("Hello");
        message.setHeader("CamelFoo", "bar");
        message.setText("Hello World");
        message.saveChanges();

        Map<String, Object> headers = endpoint.getBinding().extractHeadersFromMail(message, exchange);

        assertFalse(headers.containsKey("CamelFoo"));
        assertEquals("Hello", headers.get("Subject"));
    }

}
