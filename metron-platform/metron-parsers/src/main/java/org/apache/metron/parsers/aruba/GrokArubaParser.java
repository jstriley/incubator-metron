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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

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

		parseCSVSection(message);
	}

	private void parseCSVSection(JSONObject json) {
		if (json.containsKey("message")) {
			String message = json.get("message").toString();
			String[] split = message.split(",");
			for (int i = 0; i < split.length; i++) {
				String[] messageSplit = split[i].split("=");
				// '.' is an not allowed in elasticseach for keys. Replace occurrences of '.' with '_'.
				messageSplit[0] = messageSplit[0].replace(".", "_");
				if (messageSplit.length == 1) {
					json.put(messageSplit[0], "");
					// Timestamp contains a comma within it so the whole timestamp is across 2 sections of the csv split
				} else if ("Timestamp".equals(messageSplit[0])) {
					String timestampFull = messageSplit[1] + split[++i];
					json.put("request_timestamp", timestampFull);
				} else if ("timestamp".equals(messageSplit[0])) {
					json.put("request_timestamp", messageSplit[1]);
					// Common.Roles can have multiple items separated by commas
					// EXample: Common.Roles=[Machine·Authenticated],·[User·Authenticated]
				} else if ("Common.Roles".equals(messageSplit[0])) {
					StringBuilder sb = new StringBuilder();
					sb.append(messageSplit[1]);
					// get all elements other elements of Common.Roles
					int count = 0;
					for (int numberOfElements = i; numberOfElements < split.length - 1 && split[numberOfElements + 1].trim().charAt(0) == '['; numberOfElements++) {
						sb.append(", " + split[numberOfElements + 1]);
						count++;
					}
					i += count; // update i to be the next value in the csv section
					json.put(messageSplit[0], sb.toString());
				} else if ("fingerprint".equals(messageSplit[0])) {
					try {
						StringBuilder sb = new StringBuilder();
						sb.append(messageSplit[1]);
						int bracketCount = getNetBracketCount(messageSplit[1]); // keep track of whether we are still in the json or not.
						int count = 0; // keep track of how many elements of split we use for fingerprint
						int numberOfElements = i;
						boolean inOption = false;
						String current;
						while (bracketCount > 0) { // should never be less than 0, but  use > 0 just in case of malformed json
							if (numberOfElements < split.length - 1 && !(split[numberOfElements + 1].contains("="))) {
								current = split[numberOfElements++ + 1].trim();
								count++;
								sb.append(", " + current);
								bracketCount += getNetBracketCount(current);
							}
						}
						i += count;
						String toPut = sb.toString();
						while (toPut.matches(".+\\d+, \\d+.+")) {
							toPut = toPut.replaceAll("(\\d+), (\\d+)", "$1,$2");
						}
						json.put(messageSplit[0], toPut);
					} catch (Exception e) {
						// if an error occurs, likely due to a malformed nested json, just store the default
						json.put(messageSplit[0], messageSplit[1]);
					}
				} else {
					json.put(messageSplit[0], messageSplit[1]);
				}
			}
		}
	}

	private int getNetBracketCount(String stringFragment) {
		int bracketCount = 0;
		for (int i = 0; i < stringFragment.length(); i++) {
			switch (stringFragment.charAt(i)) {
				case '{':
					bracketCount++;
					break;
				case '}':
					bracketCount--;
					break;
			}
		}
		return bracketCount;
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