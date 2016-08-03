package org.apache.metron.parsers.cylance;

import org.apache.metron.parsers.BasicParser;

import java.util.*;
import java.text.SimpleDateFormat;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BasicCylanceParser extends BasicParser {

    private static final Logger LOGGER = LoggerFactory.getLogger(BasicCylanceParser.class);
    private SimpleDateFormat df = new SimpleDateFormat("MMM dd yyyy HH:mm:ss");

    @Override
    public void configure(Map<String, Object> parserConfig) {}

    @Override
    public void init() {}

    @SuppressWarnings("unchecked")
    public List<JSONObject> parse(byte[] msg) {

  		String message = new String(msg);
  		List<JSONObject> messages = new ArrayList<>();
        JSONObject payload = new JSONObject();

        try {

          String[] parts = message.split(",(?![^\\(\\[]*[\\]\\)])");

          // deal with oddly formatted first part
          String[] firstRow = parts[0].split("<|>| ");
          int year = Calendar.getInstance().get(Calendar.YEAR);
          df.setTimeZone(TimeZone.getTimeZone("GMT"));
          Date date = df.parse(firstRow[2] + " " + firstRow[3] + " " + year + " " + firstRow[4]);
          long epoch = date.getTime();

          payload.put("original_string", message);
          payload.put("priority", firstRow[1]);
          payload.put("timestamp", epoch);
          payload.put("hostname", firstRow[5]);
          payload.put("process", firstRow[6]);

          String[] valueSegments;
          if (parts.length == 1){
            payload.put("repeat_count", firstRow[9]);
            String betweenBrackets = parts[0].substring(parts[0].indexOf("[")+1,parts[0].indexOf("]"));
            valueSegments = betweenBrackets.split(",");
          }
          else {
            payload.put("event_type", firstRow[9]);
            valueSegments = Arrays.copyOfRange(parts, 1, parts.length);
          }

          // deal with the rest of the parameters passed through
          for (int i = 0; i < valueSegments.length; i++){
            String[] keyValue = valueSegments[i].split(":", 2);

            if (i == valueSegments.length - 1 && keyValue[1] != null) {
              payload.put(keyValue[0].toLowerCase().trim().replace(" ", "_"), keyValue[1].substring(0, keyValue[1].length() - 4).trim());
            }
            else if (!keyValue[1].trim().isEmpty() && keyValue[0].trim().equals("Path")){
                payload.put(keyValue[0].toLowerCase().trim().replace(" ", "_"), keyValue[1].trim());
            }
            else if (!keyValue[1].trim().isEmpty()) {
                payload.put(keyValue[0].toLowerCase().trim().replace(" ", "_"), keyValue[1].replaceAll("[()]","").trim());
            }
          }
          LOGGER.debug("[Metron] Returning parsed message: " + payload);
          messages.add(payload);
          return messages;
        } catch (Exception e) {
            LOGGER.error("Failed to parse: " + message);
          throw new IllegalStateException("Unable to Parse Cylance Message: " + message + " due to " + e.getMessage(), e);
        }
    }
}
