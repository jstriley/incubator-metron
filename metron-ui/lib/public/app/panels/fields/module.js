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

/*
  ## Fields (DEPRECATED)
*/
define([
  'angular',
  'app',
  'lodash'
],
function (angular, app, _) {
  'use strict';

  var module = angular.module('kibana.panels.fields', []);
  app.useModule(module);

  module.controller('fields', function($scope) {

    $scope.panelMeta = {
      status  : "Deprecated",
      description : "You should not use this table, it does not work anymore. The table panel now"+
        "integrates a field selector. This module will soon be removed."
    };


    // Set and populate defaults
    var _d = {
      style   : {},
      arrange : 'vertical',
      micropanel_position : 'right',
    };
    _.defaults($scope.panel,_d);

    $scope.init = function() {
      // Place holder until I remove this
    };

  });
});
