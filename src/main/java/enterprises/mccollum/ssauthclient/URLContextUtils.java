package enterprises.mccollum.ssauthclient;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;

/**
 * Manages to find the base URL given some requests
 * 
 * @author smccollum
 */
@Local
@Stateless
public class URLContextUtils {

	public static final String BASE_URL_PARAM = "ServerBaseUrl";
	public static final String APP_CONTEXT_URL_PARAM = "AppContextUrl";

	public String getApplicationBaseUrl(HttpServletRequest req){
		if(!empty(req.getHeader(APP_CONTEXT_URL_PARAM))){
			/*
			 * Just use the app context url provided, piece of cake
			 */
			System.out.println("App_Url_Param: " + req.getHeader(APP_CONTEXT_URL_PARAM));
			return req.getHeader(APP_CONTEXT_URL_PARAM);
		}else if(!empty(req.getHeader(BASE_URL_PARAM))){
			/*
			 * Append the app context to the server url
			 */
			System.out.println("Base_Url_Param: " + req.getHeader(BASE_URL_PARAM)+req.getContextPath());
			return req.getHeader(BASE_URL_PARAM)+req.getContextPath();
		}else{
			/*
			 * Guess URL
			 */
			StringBuilder sb = new StringBuilder(req.getScheme());
			sb.append("://");
			sb.append(req.getServerName());
			if(req.getServerPort() != 80 && req.getServerPort() != 443)
				sb.append(":"+req.getServerPort());
			sb.append(req.getContextPath());
			String appUrl = sb.toString();
			System.out.println("Guessing base URL: "+appUrl);
			return appUrl;
		}
	}
	private boolean empty(String str){
		return (str == null || str.length() < 1);
	}
}
