package enterprises.mccollum.wmapp.ssauthclient;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import com.google.gson.Gson;

import enterprises.mccollum.wmapp.authobjects.TestUser;
import enterprises.mccollum.wmapp.authobjects.UserToken;
import enterprises.mccollum.wmapp.authobjects.UserTokenBean;

@Path("ssauthclient")
public class SSAuthClientEndpoint {
	@Context
	SecurityContext seCtx;
	
	@Inject
	UserTokenBean tokenBean;
	
	/**
	 * This endpoint is provided as a convenience for implementing token blacklisting. If a client aims a request at this endpoing, it will perform token blacklisting
	 * 
	 * The URL for it will probably end up being something like this: https://my.server.name/myservice/api/ssauthclient/blacklist
	 * 
	 * The URL /ssauthclient/blacklist is appended to the base URL of your Jax-RS project
	 * 
	 * @return
	 */
	@GET
	@Path("blacklist")
	@EmployeeTypesOnly({"*", TestUser.EMPLOYEE_TYPE})
	@Produces({MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML})
	public Response blacklistEndpoint(){
		UserToken token = ((WMPrincipal)seCtx.getUserPrincipal()).getToken();
		token.setBlacklisted(true); //set the token as blacklisted for this microservice
		token = tokenBean.save(token); //Save the blacklisted token to the database
		Logger.getLogger(SSAuthClient.SUBSYSTEM_NAME).log(Level.WARNING, "Blacklisting token: "+new Gson().toJson(token));
		return Response.ok(tokenBean.get(token.getTokenId())).build();
	}
}
