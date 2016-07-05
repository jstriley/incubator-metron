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

package org.apache.metron.parsers.ciscoacs;

import org.apache.metron.parsers.GrokParser;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.text.DateFormat;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class GrokCiscoACSParser  extends GrokParser {

    protected DateFormat dateFormat;

    private static final long serialVersionUID = 1297186928520950925L;
    private static final Logger LOGGER = LoggerFactory
            .getLogger(GrokCiscoACSParser.class);

    @Override
    protected long formatTimestamp(Object value) {
        long epochTimestamp = System.currentTimeMillis();
        if (value != null) {
            try {
                epochTimestamp = toEpoch(Calendar.getInstance().get(Calendar.YEAR)  + " " + value);
            } catch (ParseException e) {
                //default to current time
            }
        }
        return epochTimestamp;
    }

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

    @Override
    protected void postParse(JSONObject message) {
        removeEmptyFields(message);
        message.remove("timestamp_string");
        if (message.containsKey("messageGreedy")) {
            String messageValue = (String) message.get("messageGreedy");

            JSONObject toReturn = message;

            if(messageValue.substring(0,10).contains("Step")) {
                format1(toReturn, messageValue);
            }
            else {
                format2(toReturn, messageValue);
            }

            cleanJSON(toReturn, "ciscoacs");
            ArrayList<JSONObject> toReturnList = new ArrayList<>();
            toReturnList.add(toReturn);
        }
    }

    private JSONObject format1(JSONObject toReturn, String messageValue) {
        try {
            // if url is in IP form, replace url tag with ip_src_addr
            if (toReturn.containsKey("url")) {
                String ip = (String) toReturn.get("url");
                if (ip.matches("[\\.\\d]+")) {
                    toReturn.put("ip_src_addr", ip);
                    toReturn.remove("url");
                }
            }

            // sort out the fields within message
            Pattern pattern = Pattern.compile("=");

            //Matcher matcher = pattern.matcher(toReturn.get("messageGreedy").toString());
            Matcher matcher = pattern.matcher(messageValue);

            // Check first occurrences
            ArrayList<String> keys = new ArrayList<>();
            if (matcher.find()) {
                keys.add(matcher.group().toString().substring(0, matcher.group().toString().length() - 1));
            }
            //Check all occurrences
            pattern = Pattern.compile(",");
            //matcher = pattern.matcher(toReturn.get("messageGreedy").toString());
            matcher = pattern.matcher(messageValue);

            while (matcher.find()) {
                if (matcher.group().toString().equals(",timestamp=")) {
                    keys.add("log_timestamp1");
                } else {
                    keys.add(matcher.group().toString().substring(0, matcher.group().toString().length() - 1));
                }
            }

            String[] fields = messageValue.split(",");

            HashMap<String, String> pairs = new HashMap<String, String>();
            HashMap<String, String> newPairs = new HashMap<String, String>();
            JSONObject steps = new JSONObject();
            JSONObject cmdArgAV = new JSONObject();
            int stepCounter = 0;

            for (int i = 0; (i < fields.length) && (i < keys.size()); i++) {
                String[] pairArray = fields[i].split("=");
                String[] subPairArray;

                if ("Step".equals(pairArray[0].replaceAll("\\s+", ""))) {
                    stepCounter++;
                    steps.put((pairArray[0] + "" + stepCounter).replaceAll("\\s+", ""), pairArray[1].replaceAll("\\s+", ""));
                }
                if ("CmdSet".equals(pairArray[0].replaceAll("\\s+", ""))) {
                    String cmdSet = fields[i].substring(fields[i].indexOf("["));
                    subPairArray = cmdSet.split(" ");
                    String[] innerPairArray;

                    int cmdArgAVCcounter = 0;

                    for (int z = 0; z < subPairArray.length; z++) {
                        if (subPairArray[z].contains("=")) {
                            innerPairArray = subPairArray[z].split("=");
                            if ("CmdArgAV".equals(innerPairArray[0].replaceAll("\\s+", ""))) {
                                cmdArgAV.put((innerPairArray[0] + "" + cmdArgAVCcounter).replaceAll("\\s+", ""), innerPairArray[1].replaceAll("\\s+", ""));
                                cmdArgAVCcounter++;
                            }

                            newPairs.put(innerPairArray[0].replaceAll("\\s+", ""), innerPairArray[1].replaceAll("\\s+", ""));
                        }
                    }
                    newPairs.put(pairArray[0].replaceAll("\\s+", ""), cmdSet.replaceAll("\\s+", ""));
                }
                if ("Response".equals(pairArray[0].replaceAll("\\s+", ""))) {
                    String cmdSet = fields[i].substring(fields[i].indexOf("{") + 1);
                    subPairArray = cmdSet.split(";");
                    String[] innerPairArray;

                    int cmdArgAVCcounter = 0;

                    for (int z = 0; z < subPairArray.length; z++) {
                        if (subPairArray[z].contains("=")) {
                            innerPairArray = subPairArray[z].split("=");

                            if ("Type".equals(innerPairArray[0].replaceAll("\\s+", ""))) {
                                cmdArgAV.put((innerPairArray[0] + "" + cmdArgAVCcounter).replaceAll("\\s+", ""), innerPairArray[1].replaceAll("\\s+", ""));
                                cmdArgAVCcounter++;
                            }
                            if ("Author-Reply-Status".equals(innerPairArray[0].replaceAll("\\s+", ""))) {
                                cmdArgAV.put((innerPairArray[0] + "" + cmdArgAVCcounter).replaceAll("\\s+", ""), innerPairArray[1].replaceAll("\\s+", ""));
                                cmdArgAVCcounter++;
                            }

                            newPairs.put(innerPairArray[0].replaceAll("\\s+", ""), innerPairArray[1].replaceAll("\\s+", ""));
                        }
                    }
                    newPairs.put(pairArray[0].replaceAll("\\s+", ""), cmdSet.replaceAll("\\s+", ""));
                } else {
                    newPairs.put(pairArray[0].replaceAll("\\s+", ""), pairArray[1].replaceAll("\\s+", ""));
                }
            }

            newPairs.put("Response", cmdArgAV.toJSONString());
            newPairs.put("Steps", steps.toJSONString());

            Set set = newPairs.entrySet();
            // Get an iterator
            Iterator i = set.iterator();
            // Display elements
            while (i.hasNext()) {
                Map.Entry me = (Map.Entry) i.next();
                if (me.getValue() != null || me.getValue().toString().length() != 0) {
                    if ("Steps".equals(me.getKey().toString())) {
                        toReturn.put("Steps", steps);
                    } else {
                        toReturn.put((me.getKey().toString()).replaceAll("\\s+", ""), (me.getValue().toString()).replaceAll("\\s+", "")); // add the field and value
                    }
                } else {
                    toReturn.put((me.getKey().toString()), "EMPTY_FIELD");   // there was no value for this field
                }
            }

            toReturn.remove("messageGreedy"); // remove message. If something goes wrong, the message is preserved within the original_string

        } catch (Exception e) {
            LOGGER.error("Exception while adding: " + toReturn.get("original_String"), e);
        }
        return toReturn;
    }

    private JSONObject format2(JSONObject toReturn, String messageValue) {
        try {
            // if url is in IP form, replace url tag with ip_src_addr
            if (toReturn.containsKey("url")) {
                String ip = (String) toReturn.get("url");
                if (ip.matches("[\\.\\d]+")) {
                    toReturn.put("ip_src_addr", ip);
                    toReturn.remove("url");
                }
            }

            // sort out the fields within message
            Pattern pattern = Pattern.compile("=");

            //Matcher matcher = pattern.matcher(toReturn.get("messageGreedy").toString());
            Matcher matcher = pattern.matcher(messageValue);

            // Check first occurrences
            ArrayList<String> keys = new ArrayList<>();
            if( matcher.find() ) {
                keys.add(matcher.group().toString().substring(0,matcher.group().toString().length()-1));
            }
            //Check all occurrences
            pattern = Pattern.compile(",");
            //matcher = pattern.matcher(toReturn.get("messageGreedy").toString());
            matcher = pattern.matcher(messageValue);

            while (matcher.find()) {
                if(matcher.group().toString().equals(",timestamp=")){
                    keys.add("log_timestamp1");
                }
                else {
                    keys.add(matcher.group().toString().substring(0,matcher.group().toString().length()-1));
                }
            }

            List<String> logMessage = new ArrayList<>();
            String firstHalf, messageClass, messageText, secondHalf, parameters, severity, messageCode, sequenceNum, timezoneOffset, eventTimestamp, eventDate;

            try {
                firstHalf = messageValue.substring(0, messageValue.indexOf(",")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("firstHalf");
                firstHalf = "";
            }

            try {
                messageClass = firstHalf.substring(firstHalf.lastIndexOf(" ", firstHalf.lastIndexOf(":")) + 1, firstHalf.lastIndexOf(":"));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("messageClass");
                messageClass = "";
            }
            try {
                messageText = firstHalf.substring(firstHalf.lastIndexOf(":") + 2, firstHalf.lastIndexOf(","));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("messageText");
                messageText = "";
            }
            try {
                secondHalf = messageValue.substring(messageValue.indexOf(",")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("secondHalf");
                secondHalf = "";
            }
            try {
                parameters = firstHalf.substring(0,firstHalf.indexOf(messageClass)-1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("parameters");
                parameters = "";
            }
            try {
                severity = parameters.substring(parameters.lastIndexOf(" ") + 1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("severity");
                severity = "";
            }
            try {
                parameters = parameters.substring(0, parameters.lastIndexOf(" "));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("parameters - part 2");
                parameters = "";
            }
            try {
                messageCode = parameters.substring(parameters.lastIndexOf(" ")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("messageCode");
                messageCode = "";
            }
            try {
                parameters = parameters.substring(0, parameters.lastIndexOf(" "));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("parameters - part 3");
                parameters = "";
            }
            try {
                sequenceNum = parameters.substring(parameters.lastIndexOf(" ")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("sequenceNum");
                sequenceNum = "";
            }
            try {
                parameters = parameters.substring(0,parameters.lastIndexOf(" "));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("parameters - part 4");
                parameters = "";
            }
            try {
                timezoneOffset = parameters.substring(parameters.lastIndexOf(" ")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("timezoneOffset");
                timezoneOffset = "";
            }
            try {
                parameters = parameters.substring(0,parameters.lastIndexOf(" "));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("parameters - part 5");
                parameters = "";
            }
            try {
                eventTimestamp = parameters.substring(parameters.lastIndexOf(" ")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("eventTimestamp");
                eventTimestamp = "";
            }
            try {
                parameters = parameters.substring(0,parameters.lastIndexOf(" "));
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("parameters - part 6");
                parameters = "";
            }
            try {
                eventDate = parameters.substring(parameters.lastIndexOf(" ")+1);
            } catch (StringIndexOutOfBoundsException e) {
                logMessage.add("eventDate");
                eventDate = "";
            }

            if (logMessage.size() > 0) {
                StringBuilder logMessageBuilder = new StringBuilder();
                for (String str : logMessage) {
                    logMessageBuilder.append(", " + str);
                }
                String logMessageString = logMessageBuilder.toString().replaceFirst(", ", "");
                LOGGER.info("Unable to parse the following: " + logMessageString + ". This is likely because this information did not exist in the log file.");
            }

            toReturn.put("messageClass",messageClass);
            toReturn.put("messageText",messageText);
            toReturn.put("eventDate",eventDate);
            toReturn.put("eventTimestamp",eventTimestamp);
            toReturn.put("timezoneOffset",timezoneOffset);
            toReturn.put("sequenceNum",sequenceNum);
            toReturn.put("messageCode",messageCode);
            toReturn.put("severity",severity);

            String[] fields = secondHalf.split(",");

            HashMap<String, String> newPairs = new HashMap<>();
            JSONObject steps = new JSONObject();
            JSONObject cmdArgAV = new JSONObject();
            int stepCounter = 0;

            for (int i = 0; (i < fields.length) && (i < keys.size()); i++) {

                String[] pairArray = fields[i].split("=");
                String[] subPairArray;

                if("Step".equals(pairArray[0].replaceAll("\\s+", ""))) {
                    stepCounter++;
                    steps.put((pairArray[0]+""+stepCounter).replaceAll("\\s+", ""),pairArray[1].replaceAll("\\s+", ""));
                }
                if("CmdSet".equals(pairArray[0].replaceAll("\\s+", ""))) {
                    String cmdSet = fields[i].substring(fields[i].indexOf("["));
                    subPairArray = cmdSet.split(" ");
                    String[] innerPairArray;

                    int cmdArgAVCcounter = 0;

                    for(int z = 0; z < subPairArray.length; z++) {
                        if(subPairArray[z].contains("=")) {
                            innerPairArray = subPairArray[z].split("=");

                            if("CmdArgAV".equals(innerPairArray[0].replaceAll("\\s+", ""))) {
                                cmdArgAV.put((innerPairArray[0]+""+cmdArgAVCcounter).replaceAll("\\s+", ""),innerPairArray[1].replaceAll("\\s+", ""));
                                cmdArgAVCcounter++;
                            }

                            newPairs.put(innerPairArray[0].replaceAll("\\s+", ""),innerPairArray[1].replaceAll("\\s+", ""));
                        }
                    }
                    newPairs.put(pairArray[0].replaceAll("\\s+", ""),cmdSet.replaceAll("\\s+", ""));
                }
                if("Response".equals(pairArray[0].replaceAll("\\s+", ""))) {
                    String cmdSet = fields[i].substring(fields[i].indexOf("{")+1);
                    subPairArray = cmdSet.split(";");
                    String[] innerPairArray;

                    int cmdArgAVCcounter = 0;

                    for(int z = 0; z < subPairArray.length; z++) {
                        if(subPairArray[z].contains("=")) {
                            innerPairArray = subPairArray[z].split("=");

                            if("Type".equals(innerPairArray[0].replaceAll("\\s+", ""))) {
                                cmdArgAV.put((innerPairArray[0]+""+cmdArgAVCcounter).replaceAll("\\s+", ""),innerPairArray[1].replaceAll("\\s+", ""));
                                cmdArgAVCcounter++;
                            }
                            if("Author-Reply-Status".equals(innerPairArray[0].replaceAll("\\s+", ""))) {
                                cmdArgAV.put((innerPairArray[0]+""+cmdArgAVCcounter).replaceAll("\\s+", ""),innerPairArray[1].replaceAll("\\s+", ""));
                                cmdArgAVCcounter++;
                            }

                            newPairs.put(innerPairArray[0].replaceAll("\\s+", ""),innerPairArray[1].replaceAll("\\s+", ""));
                        }
                    }
                    newPairs.put(pairArray[0].replaceAll("\\s+", ""),cmdSet.replaceAll("\\s+", ""));
                }
                else {
                    newPairs.put(pairArray[0].replaceAll("\\s+", ""),pairArray[1].replaceAll("\\s+", ""));
                }
            }

            newPairs.put("Response",cmdArgAV.toJSONString());
            newPairs.put("Steps",steps.toJSONString());

            Set set = newPairs.entrySet();
            // Get an iterator
            Iterator i = set.iterator();
            // Display elements
            while(i.hasNext()) {
                Map.Entry me = (Map.Entry)i.next();
                if (me.getValue() != null || me.getValue().toString().length() != 0) {
                    if ("Steps".equals(me.getKey().toString())) {
                        toReturn.put("Steps", steps);
                    } else {
                        toReturn.put((me.getKey().toString()).replaceAll("\\s+", ""), (me.getValue().toString()).replaceAll("\\s+", "")); // add the field and value
                    }
                } else {
                    toReturn.put((me.getKey().toString()), "EMPTY_FIELD");   // there was no value for this field
                }
            }

        } catch (Exception e) {
            LOGGER.error("Exception while adding: " + toReturn.get("original_string"), e);
        }

        toReturn.remove("messageGreedy"); // remove message. If something goes wrong, the message is preserved within the original_string
        return toReturn;
    }

    /**
     * Cleans the json created by the parser
     * @param parsedJSON the json that the parser created
     * @param sourceType The source type of the log
     */
    protected void cleanJSON(JSONObject parsedJSON, String sourceType) {
        removeEmptyAndNullKeys(parsedJSON);
        removeUnwantedKey(parsedJSON);
    }

    /**
     * Removes the 'UNWANTED' key from the json
     * @param parsedJSON the json the parser created
     */
    private void removeUnwantedKey(JSONObject parsedJSON) {
        parsedJSON.remove("UNWANTED");
    }

    /**
     * Removes empty and null keys from the json
     * @param parsedJSON the json the parser created
     */
    private void removeEmptyAndNullKeys(JSONObject parsedJSON) {
        Iterator<Object> keyIter = parsedJSON.keySet().iterator();
        while (keyIter.hasNext()) {
            Object key = keyIter.next();
            Object value = parsedJSON.get(key);
            // if the value is null or an empty string, remove that key.
            if (null == value || "".equals(value.toString())) {
                keyIter.remove();
            }
        }
    }
}