package enterprises.mccollum.wmapp.ssauthclient;

import javax.ejb.Local;
import javax.ejb.Stateless;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import enterprises.mccollum.wmapp.authobjects.TestUser;

/**
 * This is a catch-all for code used on servers implementing M_E auth systems
 * @author smccollum
 *
 */
@Local
@Stateless
public class SSAuthClient {

	public static final String SUBSYSTEM_NAME = "SSAuthClient";
	public static final String TEST_EMPLOYEETYPE = TestUser.EMPLOYEE_TYPE;
	
	public static String authServerUrl;
	
	Gson gsonWithExclusions;
	public static final String PRINCIPAL_SESSION_ATTRIBUTE = "sessionPrincipal";
	
	public static final String JWT_MEDIA_TYPE = "application/jwt";
	
	public SSAuthClient(){
		gsonWithExclusions = new GsonBuilder().excludeFieldsWithoutExposeAnnotation().create();
	}
	
	public Gson getGsonWithExclusions(){
		return gsonWithExclusions;
	}
}
