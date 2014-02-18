package sslcheck.core;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class NotaryConfiguration {
	
	private final static Logger log = LogManager.getLogger("core.NotaryConfiguration");
	
	Properties param = null;
	
	private static NotaryConfiguration instance = null;
	HashMap<String,ArrayList<String>> notaryConfs = new HashMap<String,ArrayList<String>>();
	
	public static NotaryConfiguration getInstance() { // NotarConfiguration is a singleton!!
		if(instance == null)
			try {
				instance = new NotaryConfiguration();
			} catch (IOException e) {
				log.error("Error instanciating NotaryConfiguration(): "+e);
			}
		return instance;
	}
	
	public NotaryConfiguration() throws IOException {
		this.param = new Properties();
		InputStream istream = this.getClass()
		        .getResourceAsStream("/notaries.properties");
		this.param.load(istream);
		istream.close();
		
		Enumeration<Object> params = this.param.keys();
		log.debug("Size of notaries.properties file: "+this.param.size());
		
		while(params.hasMoreElements()) {
			String p = ((String) params.nextElement()); // Please surround me with try-catch..
			log.debug("Parsing config value... "+p);
			int idx = p.indexOf(".");
			if(idx!=-1) {
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
	}
	
	public String getValue(String key, String notary) throws NotaryConfigurationException { 
		String ret = this.param.getProperty(notary + "." + key);
		if(ret==null) {
			log.warn("Property "+notary+"."+key+" not found, trying DefaultNotary."+key+".");
			return getValue(key);
		}
		return ret;
	}
	
	public String getValue(String key) throws NotaryConfigurationException {
		String ret = this.param.getProperty("DefaultNotary." + key);
		if(ret==null) {
			log.error("Property DefaultNotary."+key+" not found.");
			throw new NotaryConfigurationException("DefaultNotary."+key+" not found.");
		}
		return ret;
	}
	
	public ArrayList<String> getNotariesFromConfiguration() {
		return new ArrayList<String>(this.notaryConfs.keySet());
	}
	
	public String getName(String notary) {
		return this.param.getProperty(notary + ".name",this.param.getProperty("DefaultNotary.defaultName","defaultName"));
	}

}
