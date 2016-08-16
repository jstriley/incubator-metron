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

package org.apache.metron.parsers.unixsyslog5424;

import org.apache.metron.parsers.GrokParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.ParseException;
import java.util.Iterator;
import java.util.Map;

public class GrokUnixSyslog5424Parser extends GrokParser {

	private static final long serialVersionUID = 367822397082130701L;
	private static final Logger LOGGER = LoggerFactory.getLogger(GrokUnixSyslog5424Parser.class);

	// This value ("-") represents the absence of a value in RFC5424 format.
	// any field who's string value is "-" should be absent from the parser's output
	private static final String NIL_VALUE = "-";

	@Override
	protected long formatTimestamp(Object value) {
		long epochTimestamp = System.currentTimeMillis();
		if (value != null) {
			try {
				String timestamp = (String)value;
				if(!timestamp.contains(".")){
					timestamp += ".000";
				}
				// FIXME The RFC allows arbitrary precision fractions of seconds.  This code needs to support that.
				int missingzeros = "yyyy-dd-mmThh:mm:ss.sss".length() - timestamp.length();
				timestamp += new String(new char[missingzeros]).replace("\0", "0"); // add on the missing zeros

				epochTimestamp = toEpoch(timestamp);
			} catch (ParseException e) {
				//default to current time
				LOGGER.warn("Failed to parse timestamp \"" + value + "\".  Using current time instead.");
			}
		}
		return epochTimestamp;
	}

	@Override
	protected void postParse(JSONObject message) {
		removeEmptyFields(message);
		message.remove("timestamp_string");
		if (message.containsKey("structured_data")) {
			// TODO Parse structured data as specified in the RFC into the JSON object.
			LOGGER.warn("RFC5424 structured data is not yet parsed.");
		}
		Object priority = message.get("priority");
		if (priority !=null && priority instanceof Integer) {
			int realPriority = (Integer)priority;
			int severity = realPriority % 24;
			int facility = (realPriority-severity)/24;
			if (severity >= 0 && severity <= 7 && facility >=0 && facility <=23) {
				//severity and facility values are within RFC 5424 parameters.  Treat them as valid.
				message.put("severity", severity);
				message.put("facility", facility);
			}
		}
	}
	

	// FIXME This was copied, with minimal modification to use JSONObject's superclass Map instead, from GrokBluecoatProxyParser.
	// This should probably be in the base class GrokParser, or else be in a class which extends GrokParser
	// which is in turn extended by other parsers that use it, or at least in some utility class..
    private void removeEmptyFields(Map<Object, Object> map) {
        LOGGER.debug("removing unnecessary fields");
        Iterator<Object> keyIter = map.keySet().iterator();
        while (keyIter.hasNext()) {
            Object key = keyIter.next();
            Object value = map.get(key);
            if (null == value || "".equals(value.toString()) || NIL_VALUE.equals(value.toString())) {
                keyIter.remove();
            }
        }
    }

}
