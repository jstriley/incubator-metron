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

//TODO: Add tons of logging to this class and the other GRPC classes!

package org.apache.metron.enrichment.adapters.grpc;

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
  protected static final Logger _LOG = LoggerFactory.getLogger(GrpcClientAdapter.class.getName());

  //Default values for host and port
  final String DEFAULT_HOST = "localhost";
  final int DEFAULT_PORT = 50051;

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
    _LOG.info("Sending the following feature to the enrichment server: " + feature);

    //Gets the score from the enrichment server
    double score = 0;
    try {
      score = client.getEnrichment(feature);
    } catch (Exception e) {
      _LOG.error("Exception thrown when trying to get enrichment score: " + e.getMessage(), e);
    }

    //Log unscored records
    if (score == 0) {
      _LOG.info("No score returned for feature " + feature);
    }

    //Adds fields to the enrichment JSON to return
    _LOG.info("Received the following score from the enrichment server: " + score);
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

    //Create the host and port variables
    String host;
    int port = 0;

    //Try to set the port from the configuration object
    //Use default value if it fails
    try {
      port = config.getPort();
    } catch (Exception e) {
      _LOG.warn("Port variable was not set in GRPC adapter");
      _LOG.warn("Exception: " + e.getMessage(), e);
      _LOG.warn("Initializing adapter with default port: 50051");
      port = DEFAULT_PORT;
    }

    //Try to set the host from the configuration object
    //Use defauly value if it fails
    if (null == config.getHost()) {
      _LOG.warn("Host variable was not set in GRPC adapter");
      _LOG.warn("Initializing adapter with default host: localhost");
      host=DEFAULT_HOST;
    }
    else {
      host = config.getHost();
    }

    //Checks to ensure that host and port are set, fails otherwise
    if (host==null || port == 0) {
      _LOG.error("Could not initialize adapter. Host or port value was not set.");
      return false;
    }

    //Initializes the GRPC client
    _LOG.info("Intializing GRPC adapter to use " + host + ":" + port);
    client = new EnrichmentClient(host, port);
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
      _LOG.info("Shutting down GRPC client");
      client.shutdown();
    } catch (InterruptedException e) {
      _LOG.error("Could not shut down GRPC client properly due to: " + e.getMessage(), e);
    }
  }


}
