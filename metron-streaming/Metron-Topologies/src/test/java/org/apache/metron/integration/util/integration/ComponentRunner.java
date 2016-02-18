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
package org.apache.metron.integration.util.integration;

import backtype.storm.utils.Utils;

import java.util.LinkedHashMap;
import java.util.Map;

public class ComponentRunner {
    public static class Builder {
        LinkedHashMap<String, InMemoryComponent> components;
        String[] startupOrder;
        String[] shutdownOrder;
        public Builder() {
            components = new LinkedHashMap<String, InMemoryComponent>();
        }

        public Builder withComponent(String name, InMemoryComponent component) {
            components.put(name, component);
            return this;
        }

        public Builder withCustomStartupOrder(String[] startupOrder) {
            this.startupOrder = startupOrder;
            return this;
        }
        public Builder withCustomShutdownOrder(String[] shutdownOrder) {
            this.shutdownOrder = shutdownOrder;
            return this;
        }
        private static String[] toOrderedList(Map<String, InMemoryComponent> components) {
            String[] ret = new String[components.size()];
            int i = 0;
            for(String component : components.keySet()) {
                ret[i++] = component;
            }
            return ret;
        }
        public ComponentRunner build() {
            if(shutdownOrder == null) {
                shutdownOrder = toOrderedList(components);
            }
            if(startupOrder == null) {
                startupOrder = toOrderedList(components);
            }
            return new ComponentRunner(components, startupOrder, shutdownOrder);
        }

    }

    LinkedHashMap<String, InMemoryComponent> components;
    String[] startupOrder;
    String[] shutdownOrder;
    public ComponentRunner( LinkedHashMap<String, InMemoryComponent> components
                          , String[] startupOrder
                          , String[] shutdownOrder
                          )
    {
        this.components = components;
        this.startupOrder = startupOrder;
        this.shutdownOrder = shutdownOrder;

    }

    public <T extends InMemoryComponent> T getComponent(String name, Class<T> clazz) {
        return clazz.cast(getComponents().get(name));
    }

    public LinkedHashMap<String, InMemoryComponent> getComponents() {
        return components;
    }

    public void start() throws UnableToStartException {
        for(String componentName : startupOrder) {
            components.get(componentName).start();
        }
    }
    public void stop() {
        for(String componentName : shutdownOrder) {
            components.get(componentName).stop();
        }
    }

    public <T> T process(Processor<T> successState) {
        return process(successState, 5, 30000, 120000);
    }

    public <T> T process(Processor<T> successState, int numRetries, long timeBetweenAttempts, long maxTimeMs) {
        int retryCount = 0;
        long start = System.currentTimeMillis();
        while(true) {
            long duration = System.currentTimeMillis() - start;
            if(duration > maxTimeMs) {
                throw new RuntimeException("Took too long to complete: " + duration + " > " + maxTimeMs);
            }
            ReadinessState state = successState.process(this);
            if(state == ReadinessState.READY) {
                return successState.getResult();
            }
            else if(state == ReadinessState.NOT_READY) {
                retryCount++;
                if(numRetries > 0 && retryCount > numRetries) {
                    throw new RuntimeException("Too many retries: " + retryCount);
                }
            }
            Utils.sleep(timeBetweenAttempts);
        }
    }


}
