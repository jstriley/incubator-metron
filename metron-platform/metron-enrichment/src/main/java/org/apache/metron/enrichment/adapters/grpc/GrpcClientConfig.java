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

import java.io.Serializable;

/**
 * This class serves as a configuration object for
 * a GRPC Client Adapter
 *
 * It contains a host and a port to use to contact
 * the GRPC server
 */
public class GrpcClientConfig implements Serializable {

  //Config fields must be public so that flux can access them
  public String host;
  public int port;

  public String getHost() {
    return host;
  }

  public int getPort() {
    return port;
  }

  public GrpcClientConfig withHost(String host) {
    this.host = host;
    return this;
  }

  public GrpcClientConfig withPort(int port) {
    this.port = port;
    return this;
  }

}
