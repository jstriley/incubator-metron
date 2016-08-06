/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.metron.parsers.radware;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.json.simple.JSONObject;
import org.junit.Before;
import org.junit.Test;

public class GrokRadWareParserTest {

    private Map<String, Object> parserConfig;

    @Before
    public void setup() {
        parserConfig = new HashMap<>();
        parserConfig.put("grokPath", "/Users/onb813/incubator-metron/metron-platform/metron-parsers/src/main/resources/patterns/radware");
        parserConfig.put("patternLabel", "RADWARE");
        parserConfig.put("timestampField", "timestamp_string");
        parserConfig.put("dateFormat", "dd-MM-yyyy HH:mm:ss");

    }


    @Test
    public void testParseLoginLine() throws Exception {

        //Set up parser, parse message
        GrokRadWareParser parser = new GrokRadWareParser();
        parser.configure(parserConfig);
        String testString = "<180>DefensePro: 21-03-2016 21:55:05 WARNING 432 Anti-Scanning \"TCP Scan (horizontal)\" TCP 114.122.2.201 0 0.0.0.0 8080 0 Regular \"Catch All\" ongoing 2 0 N/A 0 N/A medium drop AAAAAAAAAAAA-AAAA-AD8B-0004555104DD";
        List<JSONObject> result = parser.parse(testString.getBytes());
        JSONObject parsedJSON = result.get(0);
        System.out.println(parsedJSON);
        assertEquals("180", parsedJSON.get("priority") + "");
        assertEquals("1458597305000", parsedJSON.get("timestamp") + "");
        assertEquals("WARNING", parsedJSON.get("severity") + "");
        assertEquals("432", parsedJSON.get("radwareID") + "");
        assertEquals("Anti-Scanning", parsedJSON.get("category") + "");
        assertEquals("TCP Scan (horizontal)", parsedJSON.get("event_name") + "");
        assertEquals("TCP", parsedJSON.get("protocol") + "");
        assertEquals("114.122.2.201", parsedJSON.get("ipSrc") + "");
        assertEquals("0", parsedJSON.get("srcPort") + "");
        assertEquals("0.0.0.0", parsedJSON.get("ipDest") + "");
        assertEquals("8080", parsedJSON.get("destPort") + "");
        assertEquals("0", parsedJSON.get("physicalPort") + "");
        assertEquals("Regular", parsedJSON.get("context") + "");
        assertEquals("Catch All", parsedJSON.get("policy") + "");
        assertEquals("ongoing", parsedJSON.get("eventType") + "");
        assertEquals("2", parsedJSON.get("packetCount") + "");
        assertEquals("0", parsedJSON.get("bandwidth") + "");
        assertEquals("N/A", parsedJSON.get("vlanTag") + "");
        assertEquals("0", parsedJSON.get("mplsRd") + "");
        assertEquals("N/A", parsedJSON.get("mplsTag") + "");
        assertEquals("medium", parsedJSON.get("risk") + "");
        assertEquals("drop", parsedJSON.get("action") + "");
        assertEquals("AAAAAAAAAAAA-AAAA-AD8B-0004555104DD", parsedJSON.get("unique_id") + "");
    }

}