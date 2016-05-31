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

package org.apache.metron.parsers.aruba;

import java.text.ParseException;
import java.util.Iterator;

import org.apache.metron.parsers.GrokParser;
import org.json.simple.JSONObject;

public class GrokArubaParser extends GrokParser {

	private static final long serialVersionUID = 3975493065728576059L;

	//Removes empty fields, formats the timestamp, tags IPs
	@Override
	@SuppressWarnings("unchecked")
	protected void postParse(JSONObject message) {
		removeEmptyFields(message);
		convertTimestamp(message);
		if(message.containsKey("url")) {
			String url = (String) message.get("url");
			if(url.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
				message.remove("url");
				message.put("ip_src_addr", url);
			}
		}
	}

	//Removes any keys with empty or null values
	@SuppressWarnings("unchecked")
	private void removeEmptyFields(JSONObject json) {
		Iterator<Object> keyIter = json.keySet().iterator();
		while (keyIter.hasNext()) {
			Object key = keyIter.next();
			Object value = json.get(key);
			if (null == value || "".equals(value.toString())) {
				keyIter.remove();
			}
		}
	}

	//Converts a timestamp to a long using the provided date format
	@SuppressWarnings("unchecked")
	protected void convertTimestamp(JSONObject json) {
		long epochTimestamp = System.currentTimeMillis();
		if (json.containsKey("timestamp_string")) {
			String timestamp = (String) json.get("timestamp_string");
			if (timestamp != null) {
				try {
					epochTimestamp = toEpoch(timestamp);
				} catch (ParseException e) {
					//default to current time
				}
			}
		}
		json.remove("timestamp_string");
		json.put("timestamp", epochTimestamp);
	}
}