package sslcheck.notaries;

import java.io.FileInputStream;
import java.io.BufferedInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

public class NotaryConfiguration {
	
	Properties param = null;
	
	private static NotaryConfiguration instance = null;
	HashMap<String,ArrayList<String>> notaryConfs = new HashMap<String,ArrayList<String>>();
	
	public static NotaryConfiguration getInstance() { // NotarConfiguration is a singleton!!
		if(instance == null)
			try {
				return new NotaryConfiguration();
			} catch (IOException e) {
				e.printStackTrace();
			}
		return instance;
	}
	
	public NotaryConfiguration() throws IOException {
		this.param = new Properties();
		BufferedInputStream stream = new BufferedInputStream(new FileInputStream("notaries.properties"));
		this.param.load(stream);
		stream.close();
		
		Enumeration<Object> params = this.param.elements();
		
		while(params.hasMoreElements()) {
			String p = ((String) params.nextElement()); // Please surround me with try-catch..
			int idx = p.indexOf(".");
			String p_name = p.substring(0,idx);
			String p_confVariable = p.substring(idx+1, p.length()-1);
			
			if(!this.notaryConfs.containsKey(p_name)){
				ArrayList<String> variables = new ArrayList<String>();
				variables.add(p_confVariable);
				notaryConfs.put(p_name,variables);	
			}else{
				ArrayList<String> variables = this.notaryConfs.get(p_name);
				this.notaryConfs.remove(p_name);
				variables.add(p_confVariable);
				notaryConfs.put(p_name,variables);	
			}	
		}
	}

	public float getRatingFactor(String notary) { 
		String factor = this.param.getProperty(notary + ".ratingFactor",this.param.getProperty("DefaultNotary.ratingFactor"));
		return Float.parseFloat(factor.trim()); // TODO catch exceptions..
	}
	
	public int getMinRating(String notary) {
		String factor = this.param.getProperty(notary + ".resultMin",this.param.getProperty("DefaultNotary.ratingFactor","1"));
		return Integer.parseInt(factor.trim()); // TODO catch exceptions..
	}

	public int getMaxRating(String notary) {
		String factor = this.param.getProperty(notary + ".resultMin",this.param.getProperty("DefaultNotary.ratingFactor","1"));
		return Integer.parseInt(factor.trim()); // TODO catch exceptions..
	}
	
	public boolean isEnabled(String notary) {
		return (this.param.getProperty(notary + ".enabled","false").equals("true"));
	}
	
	public ArrayList<String> getNotariesFromConfiguration() {
		return new ArrayList<String>(this.notaryConfs.keySet());
	}
	
	public String getName(String notary) {
		return this.param.getProperty(notary + ".name",this.param.getProperty("DefaultNotary.defaultName","defaultName"));
	}

}
