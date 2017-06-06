package enterprises.mccollum;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

/**
 * Deals with the creation and deletion of cookies
 * 
 * @author smccollum
 */
public class CookieUtils {
	/**
	 * Sets/creates a cookie
	 * 
	 * @param res: {@link HttpServletResponse} this belongs to
	 * @param cookieName: The name of the cookie
	 * @param value: The value of the cookie
	 * @param expirationDate: The expiration date and time in java millisecond-precision as returned by {@code System.currentTimeMillis();}
	 */
	public static void setCookie(HttpServletResponse res, String cookieName, String value, Long expirationDate){
		int expiry = (int) ((expirationDate - System.currentTimeMillis())/1000);
		Cookie cookie = new Cookie(cookieName, value);
		cookie.setPath("/");
		cookie.setVersion(1);
		cookie.setMaxAge(expiry);
		res.addCookie(cookie);
	}
	
	/**
	 * Delete a cookie
	 * 
	 * @param res: {@link HttpServletResponse} this cookie is in
	 * @param cookieName: The name of the cookie to delete
	 */
	public static void deleteCookie(HttpServletResponse res, String cookieName){
		Cookie cookie = new Cookie(cookieName, null);
		cookie.setPath("/");
		cookie.setMaxAge(0);
		res.addCookie(cookie);
	}
}
