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

package org.apache.metron.parsers.windowssyslogjson;

import java.util.Iterator;
import java.util.Map;

import org.apache.metron.parsers.unixsyslog5424.GrokUnixSyslog5424Parser;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.base.CaseFormat;

/**
 * Metron Message Parser for Windows Event Logs formatted as a JSON message body within a Syslog (RFC 5424) message.
 *
 * @author Jonathon Striley for Capital One
 *
 */
public class WindowsSyslogJSONParser extends GrokUnixSyslog5424Parser {

	private static final long serialVersionUID = -535234013637774698L;
	private static final Logger LOGGER = LoggerFactory.getLogger(WindowsSyslogJSONParser.class);

	@Override
	protected void postParse(JSONObject message) {
		super.postParse(message);
		String syslogMessageComponent = (String) message.get("message");
		message.remove("message");
		
		// rename version field to syslog_version
		message.put("syslog_version", message.get("version"));
		message.remove("version");

		try {
			System.out.println("FINDME: " + syslogMessageComponent);
			JSONObject result = (JSONObject) new JSONParser().parse(syslogMessageComponent);
			// move data from "message" field into output object
			for (Object key: result.keySet()) {
				// TODO implement any field renaming here
				
				// If the key has a non-empty value, add it to the message
				if (result.get(key) != null && result.get(key).toString().length() > 0) {
					Object cleanedKeyName = cleanKey(key);
					message.put(cleanedKeyName, result.get(key));					
				}
			}
			
			// TODO Need to add some handling of login & logout messages (parsing of "Message" field in JSON within syslog message field.)
			//      see WindowsSyslogParser for logic.
			
		} catch (ParseException e) {
			LOGGER.warn("Unable to parse JSON message component of Windows event as JSON over Syslog message:", e);
		}
		
		
	}
	
	/**
	 * We could probably implement this better using something in commons-lang's StringUtils
	 * or something, and do it more efficiently.  Also, I think there are other parsers that could use this.
	 * Still, here's something to sanitize key names.
	 * 
	 * @param key
	 * @return a sanitized version of the key name
	 */
	private static Object cleanKey(Object key) throws ParseException {
		/* FIXME Technically the json ParseException is for errors parsing the JSON, so something else may be more appropriate
		 * here.  The -1 position value when instantiating the ParseExceptions is unnatural. */

		if (!(key instanceof String)) {
			throw new ParseException(-1, "Invalid JSON.  Non-String keyname.");
		}
		String dirtyKeyName = (String)key;
		if (dirtyKeyName.length() < 1) {
			throw new ParseException(-1, "Invalid JSON.  Zero length key name.");
		}

		return CaseFormat.UPPER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, dirtyKeyName);

	}
	

	// FIXME This was copied, with minimal modification to use JSONObject's superclass Map instead, from GrokBluecoatProxyParser.
	// This should probably be in the base class GrokParser, or else be in a class which extends GrokParser
	// which is in turn extended by other parsers that use it, or at least in some utility class..
    @SuppressWarnings("unchecked")
    private void removeEmptyFields(Map map) {
        LOGGER.debug("removing unnecessary fields");
        Iterator<Object> keyIter = map.keySet().iterator();
        while (keyIter.hasNext()) {
            Object key = keyIter.next();
            Object value = map.get(key);
            if (null == value || "".equals(value.toString()) || "-".equals(value.toString())) {
                keyIter.remove();
            }
        }
    }


//	private static void main (String args[]) {
//		WindowsSyslogJSONParser parser = new WindowsSyslogJSONParser();
//		HashMap<String,Object> parserConfig = new HashMap<>();
//		parserConfig.put("grokPath", "../metron-parsers/src/main/resources/patterns/unixsyslog5424");
//		parserConfig.put("patternLabel", "UNIXSYSLOG5424");
//		parserConfig.put("timestampField", "timestamp_string");
//		parserConfig.put("dateFormat", "yyyy-MM-dd'T'HH:mm:ss.SSS");
//		parser.configure(parserConfig);
//		parser.parse("");
//	}
}
