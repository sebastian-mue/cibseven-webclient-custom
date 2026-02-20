/*
 * Copyright CIB software GmbH and/or licensed to CIB software GmbH
 * under one or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information regarding copyright
 * ownership. CIB software licenses this file to you under the Apache License,
 * Version 2.0; you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.cibseven.webapp.rest;

import java.util.Collection;
import java.util.Collections;

import org.cibseven.webapp.rest.model.Engine;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;

@ApiResponses({
	@ApiResponse(responseCode = "500", description = "An unexpected system error occurred")
})
@RestController
@RequestMapping("${cibseven.webclient.services.basePath:/services/v1}" + "/engine")
public class EngineService extends BaseService {

	/**
	 * Configurable engine name from properties file.
	 * This property allows overriding the engine name without querying the Camunda REST API.
	 * Default value is "default" if not specified in cibseven-webclient.properties.
	 * 
	 * The engine name should match the process engine name configured in the WildFly/JBoss
	 * standalone-full.xml file under:
	 * {@code <subsystem xmlns="urn:org.cibseven.bpm.jboss:1.1">}
	 *   {@code <process-engines>}
	 *     {@code <process-engine name="default" default="true">}
	 * 
	 * Example configuration in cibseven-webclient.properties:
	 * cibseven.engine.name=default
	 */
	@Value("${cibseven.engine.name:default}")
	private String engineName;

	/**
	 * Returns the configured process engine name.
	 * 
	 * The engine selector dropdown in the frontend (CIBHeaderFlow component) allows users to
	 * switch between different Camunda process engines when multiple engines are configured.
	 * This is useful in multi-tenant scenarios or when running multiple isolated process engines.
	 * The dropdown is only visible when more than one engine is available.
	 * 
	 * Note: This method was changed to return a static configured value instead of calling
	 * the Camunda REST API because of SPOT's authentication architecture:
	 * 
	 * Background:
	 * The Goetel SPOT application changed the Camunda REST API path from /engine-rest to /rest
	 * This change must also be configured in cibseven.webclient.engineRest.path=/rest 
	 * of the cibseven-webclient\cibseven-webclient-web\src\main\resources\application.yaml.
	 * 
	 * SPOT implements a CamundaAuthenticationFilter that intercepts ALL requests to /rest/*
	 * and enforces authentication for almost all /rest/* endpoints using stateful JWT tokens.
	 * 
	 * Problem:
	 * 1. The frontend CIBHeaderFlow component calls the /rest/engine endpoint when the login page loads
	 * 2. At that point, no user is authenticated yet (no JWT token available from Spot)
	 * 3. The original implementation called /rest/engine (SPOT's modified path)
	 * 4. SPOT's CamundaAuthenticationFilter blocks the request due to missing authentication
	 * 5. This caused authorization failures and error popups on the login page before users could even log in
	 * 
	 * Note: In standard Camunda, /engine-rest/engine doesn't require authentication, but with
	 * SPOT's /rest path and CamundaAuthenticationFilter, it now DOES require authentication.
	 * 
	 * Solution:
	 * By returning a configured static value from application properties, we avoid the unauthorized
	 * REST call while still providing the engine name needed by the frontend for the engine selector dropdown.
	 * 
	 * Configuration:
	 * - Set the engine name in cibseven-webclient.properties: cibseven.engine.name=default
	 * - The name must match the process engine name in standalone-full.xml
	 * - The engineRest.path is configured as /rest (instead of standard /engine-rest)
	 * 
	 * Related custom modifications:
	 * - SpotUserProvider (handles SPOT JWT authentication)
	 * - CIBUser.backendJwtToken (stores SPOT JWT for authenticated requests)
	 * 
	 * @return Collection containing a single Engine object with the configured name
	 */
	@Operation(summary = "Get process engine names", description = "Retrieves the names of all process engines available on the engine")
	@ApiResponse(responseCode = "200", description = "List of engine names successfully retrieved")
	@GetMapping
	public Collection<Engine> getProcessEngineNames() {
		Engine engine = new Engine();
		engine.setName(engineName);
		return Collections.singletonList(engine);
	}
}
