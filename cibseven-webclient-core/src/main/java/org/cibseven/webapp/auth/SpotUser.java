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
package org.cibseven.webapp.auth;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Custom user class for Goetel SPOT integration.
 * 
 * This class extends CIBUser to add SPOT-specific authentication fields without
 * modifying the base CIBUser class.
 * 
 * The backendJwtToken field stores the JWT token received from the Goetel SPOT backend
 * and is used for all subsequent API calls to the SPOT backend.
 * 
 * See SpotUserProvider for details on the SPOT authentication flow.
 */
@NoArgsConstructor
public class SpotUser extends CIBUser {
	
	/**
	 * Stores the JWT token received from the Goetel SPOT backend.
	 * 
	 * This field was added to support authentication against the Goetel SPOT backend system.
	 * 
	 * Background:
	 * The Goetel SPOT application changed the Camunda REST API path from /engine-rest to /rest
	 * and implements a CamundaAuthenticationFilter that intercepts ALL /rest/* requests.
	 * This filter enforces authentication using stateful JWT tokens that SPOT tracks server-side.
	 * 
	 * Standard Camunda endpoints (like /engine-rest/engine) normally don't require authentication,
	 * but with SPOT's /rest path and CamundaAuthenticationFilter, they now DO require authentication.
	 * 
	 * The authentication workflow:
	 * 1. User logs in via the webclient
	 * 2. SpotUserProvider authenticates against SPOT backend (/rest/authentication/login) with Basic Auth
	 * 3. SPOT backend validates credentials and returns a stateful JWT token
	 * 4. This token is stored here and MUST be serialized/deserialized with the user session
	 * 5. All subsequent REST API calls to /rest/* include this token as "Bearer <token>"
	 * 6. SPOT's CamundaAuthenticationFilter validates the JWT and allows the request
	 * 
	 * Without this field, the webclient cannot make authenticated calls to the SPOT backend
	 * after the initial login, as SPOT's CamundaAuthenticationFilter requires this JWT for
	 * authorization on all /rest/* endpoints.
	 * 
	 * See: SpotUserProvider.login() and SpotUserProvider.getEngineRestToken()
	 */
	@Getter @Setter
	String backendJwtToken;
	
	public SpotUser(String userId) {
		super(userId);
	}
}
