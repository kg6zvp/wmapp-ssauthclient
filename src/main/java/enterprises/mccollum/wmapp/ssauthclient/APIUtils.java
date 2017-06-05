package enterprises.mccollum.wmapp.ssauthclient;

import javax.ejb.Local;
import javax.ejb.Stateless;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

@Local
@Stateless
public class APIUtils {

	public JsonObject mkErrorEntity(String msg){
		return mkSingleResponseObject("error", msg);
	}
	
	public JsonObject mkSingleResponseObject(String responseType, String msg){
		JsonObjectBuilder job = Json.createObjectBuilder();
		job.add(responseType, msg);
		return job.build();
	}
}
