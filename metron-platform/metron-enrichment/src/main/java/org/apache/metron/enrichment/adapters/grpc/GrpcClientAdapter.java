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

package org.apache.metron.enrichment.adapters.grpc;

import org.apache.metron.enrichment.adapters.grpc.generated.Feature;
import org.apache.metron.enrichment.adapters.simplehbase.SimpleHBaseAdapter;
import org.apache.metron.enrichment.bolt.CacheKey;
import org.apache.metron.enrichment.interfaces.EnrichmentAdapter;
import org.json.simple.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.Serializable;

public class GrpcClientAdapter implements EnrichmentAdapter<CacheKey>, Serializable {

  protected EnrichmentClient client;
  protected GrpcClientConfig config;
  protected static final Logger _LOG = LoggerFactory.getLogger(SimpleHBaseAdapter.class);

  public GrpcClientAdapter(){}

  public GrpcClientAdapter(GrpcClientConfig config){
    withConfig(config);
  }

  public GrpcClientAdapter withConfig(GrpcClientConfig config){
    this.config = config;
    return this;
  }

  String host;
  int port;

  @Override
  public void logAccess(CacheKey value) {}

  /**
   * Takes in a value to be enriched, uses GRPC to reach out
   * to a server for enrichment data, and creates an enriched
   * JSON object with the data retrieved
   *
   *
   * @param value, the CacheKey containing the field for enrichment
   * @return an enriched JSON object
   */
  @Override
  public JSONObject enrich(CacheKey value) {

    //The JSON object to fill in with values and return
    JSONObject enriched = new JSONObject();

    //Checks to see if the adapter is initialized
    if (!isInitialized()) {
      initializeAdapter();
    }

    //Gets the string to send to the enrichment server
    String feature = value.getValue();

    //Gets the score from the enrichment server
    double score = client.getEnrichment(feature);

    //Adds fields to the enrichment JSON to return
    enriched.put("enrichment_timestamp", System.currentTimeMillis());
    enriched.put("feature", feature);
    enriched.put("score", score);

    return enriched;
  }

  /**
   * Creates a GRPC client to talk to the enrichment server
   *
   * @return true or false, depending on successful initialization
   */
  @Override
  public boolean initializeAdapter() {
    try {
      String host = config.getHost();
      int port = config.getPort();
      client = new EnrichmentClient(host, port);
    } catch (Exception e) {
      _LOG.error("Unable to initialize adapter: " + e.getMessage(), e);
      return false;
    }
    return true;
  }

  /**
   * Checks to see if the GRPC client is properly initialized
   *
   * @return true of false, depending on if the adapter is
   * properly initialized
   */
  public boolean isInitialized() {
    return (client != null);
  }

  /**
   * Shuts down the GRPC client
   */
  @Override
  public void cleanup() {
    try {
      client.shutdown();
    } catch (InterruptedException e) {
      _LOG.error("Could not shut down GRPC client properly due to: " + e.getMessage(), e);
    }
  }


}
