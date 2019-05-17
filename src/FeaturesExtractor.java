import java.io.BufferedReader;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.net.whois.WhoisClient;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;

import com.google.common.net.InternetDomainName;

public class FeaturesExtractor {
	
	public static double[] extract(String url, int numAttributes) {
			
			double[] features = new double[numAttributes];
			
			System.out.println("-------  START FEATURES EXTRACTION  --------");
			
			double[] addressBarFeatures = getAddressBarFeatures(url);
			double[] abnormalUrlFeatures = getAbnormalUrlFeatures(url);
			double[] documentFeatures = getDocumentFeatures(url);
			double[] domainFeatures = getDomainFeatures(url);
			int j = 0;
			
			for(int i = 0; i<addressBarFeatures.length; ++i)
				features[j++] = addressBarFeatures[i];

			for(int i = 0; i<abnormalUrlFeatures.length; ++i)
				features[j++] = abnormalUrlFeatures[i];
	
			for(int i = 0; i<documentFeatures.length; ++i)
				features[j++] = documentFeatures[i];
		
			for(int i = 0; i<domainFeatures.length; ++i)
				features[j++] = domainFeatures[i];
			
			features[features.length-1] = 1;
			
			System.out.println("-------  END  --------");

			return features;
	}
	
	private static double[] getAddressBarFeatures(String url) {
		
		double[] featuresToReturn = new double[12]; 
		
		double havingIPAddress = -1;
		double havingSubDomain = 0;
		double urlLength = 0;
		double shortiningService = -1;
		double havingAtSymbol = -1;
		double doubleSlashRedirecting = -1;
		double prefixSuffix = -1;
		double sslFinalState = 0;
		double domainRegistrationLength = -1;
		double httpsToken = -1;
		double favicon = -1;
		double port = -1;
		
		URI uri = null;
		try {
		
		uri = new URI(url);

		String hostname = uri.getHost().trim();
		
		//---- HAVING IP ADDRESS
		
		if(hostname == null) {
		    	 
			String temp = url.startsWith("https")? url.substring(8): url.startsWith("http")? url.substring(7): null;
		    	 
			havingIPAddress = (temp == null) ? -1: (Character.isDigit(temp.charAt(0)) == true) ? -1:1;
		}else
		    havingIPAddress = (hostname == null) ? -1: (Character.isDigit(hostname.charAt(0)) == true) ? -1:1;
		     
		System.out.println("Having_IP_Address = " + havingIPAddress + "\n");
		
		//---- URL LENGTH
		
		urlLength = (url.length()<54)? 1 : url.length()>75 ? -1 : 0;
		System.out.println("URL_Length = " + urlLength + "\n");
		
		//---- SHORTINING SERVICE
		
		try {
		String[] shortiningServiceDomains = {"bit.ly", "tinyurl.com", "tiny.cc","lc.chat", "is.gd","soo.gd","s2r.co"};
		String domain = getDomainFromUrl(url);
		shortiningService = Arrays.asList(shortiningServiceDomains).contains(domain)? -1 : 1;
		}catch(Exception e) {
			shortiningService = -1;
		}
		System.out.println("Shortining_Service = " + shortiningService + "\n");
		
		//---- HAVING AT SYMBOL
		
		havingAtSymbol = url.contains("@")? -1 : 1;
		System.out.println("Having_AT_Symbol = " + havingAtSymbol + "\n");
		
		//---- DOUBLE SLASH REDIRECTING
		
		doubleSlashRedirecting = url.lastIndexOf("//")>7 ? -1 : 1;
		System.out.println("Double_Slash_Redirecting = " + doubleSlashRedirecting + "\n");
		
		//---- PREFIX SUFFIX
		

		prefixSuffix = hostname.contains("-")? -1 : 1;
		System.out.println("Prefix_Suffix = " + prefixSuffix + "\n");
		
		//--- HAVING SUB DOMAIN
		
		String host_temp = hostname;
		    
		if(host_temp != null) {
		    	
			host_temp = host_temp.startsWith("www.") ? host_temp.substring(4) : host_temp;
			    
			havingSubDomain = host_temp.split("\\.").length > 3 ? -1 : host_temp.split("\\.").length == 3 ? 0 : 1;
			  
		}
		    
		System.out.println("Having_Sub_Domain = " + havingSubDomain + "\n");
		 
		//---- SSL FINAL STATE
		
		if(url.startsWith("https")) {
			try {
			
			URL destinationURL = new URL(url);
	
	        HttpsURLConnection conn = (HttpsURLConnection) destinationURL.openConnection();
	        conn.connect();
	        Certificate[] certs = conn.getServerCertificates();
	        
	        for (Certificate cert : certs) {
	            if(cert instanceof X509Certificate) {
	            	
	                Date certAge = ((X509Certificate) cert).getNotBefore();
	                Calendar cal = Calendar.getInstance();
	                cal.add(Calendar.YEAR, 2);
	                
	                if( certAge.after(cal.getTime()) ) {
	                	sslFinalState = 0;
	                	break;
	                }
	                
	                String issuer = ((X509Certificate) cert).getIssuerDN().getName().split(",")[0];
					issuer = issuer.substring(3);
					String[] trustedIssuers = {"Google Internet Authority G3", "GlobalSign", "Verisign", "Terena SSL CA 3", "DigiCert", "GeoTrust", "GoDaddy", "Network Solutions", "Comodo", "Thawte", "Doster"};
					
					if(!(Arrays.asList(trustedIssuers).contains(issuer))) {
						sslFinalState = 0;
						break;
					}
	                
	            } else {
	                sslFinalState = 0;
	                break;
	            }
	        }
	        
	        
			} catch (Exception e) {
				sslFinalState = -1;
			}
			
		}else
			sslFinalState = -1;
		
		System.out.println("SSL_Final_State = " + sslFinalState + "\n");
		
		//------ WHOIS Query: DOMAIN REGISTRATION LENGTH
		
		WhoisClient wh = new WhoisClient();
		StringBuilder resultW = new StringBuilder("");
		
		try {
			
			wh.connect(WhoisClient.DEFAULT_HOST);
			String whoisData = wh.query(getDomainFromUrl(url));
			resultW.append(whoisData);
			wh.disconnect(); 
			String st = whoisData.substring(whoisData.indexOf("Expiry Date:")+13);
			String expiryDate = st.substring(0,st.indexOf("Registrar"));
			//System.out.println(whoisData);
			
			SimpleDateFormat parser = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	        parser.setTimeZone(TimeZone.getTimeZone("UTC"));
	        Date parsed = parser.parse(expiryDate);
	        
	        Calendar cal = Calendar.getInstance();
	        cal.add(Calendar.YEAR, 1);
	        
	        domainRegistrationLength = parsed.before(parser.parse(parser.format(cal.getTime()))) ? -1:1;
	        
	        
		} catch (Exception e) {
			domainRegistrationLength = -1;
		}
		
		System.out.println("Domain_registration_length = " + domainRegistrationLength + "\n");
		
		//---- FAVICON
		
		try {
			
			Document doc = Jsoup.connect(url).get();
			Elements elements = doc.select("link");
			for(Element e : elements) {
				if(e.attr("rel").contains("icon")) {
					
					if(!(isSameDomain(url, e.attr("href").trim()))) {
						favicon = -1;
						break;
						
					}else {
						favicon = 1;
						break;
					}
						
				}
			}
			
			
		} catch (Exception e) {

			favicon = -1;
		}
		
		System.out.println("Favicon = " + favicon + "\n");
		
		
		//----- PORT
		
		int[] portToCheck = {21,22,23,80,443,445,1433,1521,3306,3389};
		boolean[] portStatus = {false, false, false, true, true, false,false,false,false,false};
	
		for (int p = 0; p<portToCheck.length; ++p) {
	          try {
	             Socket socket = new Socket();
	             socket.connect(new InetSocketAddress("localhost", portToCheck[p]),1);
	             socket.close();
	             
	             if(portStatus[p] == false) {
	            	 port = -1;
	            	 break;
	             }
	             
	         } catch (Exception ex) {
	         }
	       }
		
		System.out.println("Port = " + port + "\n");
		
		//---- HTTPS TOKEN
		httpsToken = hostname.startsWith("https")? -1 : 1;
		System.out.println("HTTPS_Token = " + httpsToken + "\n");
		
		} catch (Exception e1) {
			System.out.println("URI malformed");
		}

		
		featuresToReturn[0] = havingIPAddress;
		featuresToReturn[1] = urlLength;
		featuresToReturn[2] = shortiningService;
		featuresToReturn[3] = havingAtSymbol;
		featuresToReturn[4] = doubleSlashRedirecting;
		featuresToReturn[5] = prefixSuffix;
		featuresToReturn[6] = havingSubDomain;
		featuresToReturn[7] = sslFinalState;
		featuresToReturn[8] = domainRegistrationLength;
		featuresToReturn[9] = favicon;
		featuresToReturn[10] = port;
		featuresToReturn[11] = httpsToken;

		return featuresToReturn;
	}
	
	private static double[] getAbnormalUrlFeatures(String url) {
		
		double[] featuresToReturn = new double[6];
		
		double abnormalURL = -1;
		double requestURL = -1;
		double urlOfAnchor = 0;
		double linksInTags = 0;
		double sfh = 0;
		double submittingToEmail = -1;
		
		//---- REQUEST URL

		try {
			Document doc = Jsoup.connect(url).timeout(120*1000).get();
			
			Elements sources = doc.select("source");
			Elements audios = doc.select("audio");
			Elements videos = doc.select("video");
			Elements imgs = doc.select("img");
			ArrayList<String> tagUrls = new ArrayList<String>();
			for(Element e : sources)
				if(e.hasAttr("src")) 
					tagUrls.add(e.attr("src"));
			for(Element e : audios)
				if(e.hasAttr("src")) 
					tagUrls.add(e.attr("src"));
			for(Element e : videos)
				if(e.hasAttr("src")) 
					tagUrls.add(e.attr("src"));
			for(Element e : imgs)
				if(e.hasAttr("src")) 
					tagUrls.add(e.attr("src"));
			
			double numNotSameDomain = 0;
			for(String s : tagUrls) 
				numNotSameDomain = isSameDomain(url, s) ? numNotSameDomain : numNotSameDomain+1;
			
			if(tagUrls.size() > 0) {
				requestURL = (numNotSameDomain/tagUrls.size() *100 < 22) ? 1 : (numNotSameDomain/tagUrls.size() *100) > 61 ? -1 : 0;
			}else {
				requestURL = 1;
			}
			
		} catch (Exception e1) {
			requestURL = 1;
		}
		
		System.out.println("Request_URL = " + requestURL + "\n");
		
		//---- URL OF ANCHOR
		
		try {
			
			Document doc = Jsoup.connect(url).timeout(1000*1000).get();

			Elements anchors = doc.select("a");
        	double numNotSameDomain = 0;
        	ArrayList<String> anchorUrls = new ArrayList<String>();
        	
        	for(Element link : anchors)
        		anchorUrls.add(link.attr("href").trim());
        	
	        for (String link : anchorUrls) {
	        	numNotSameDomain = isSameDomain(url, link) ? numNotSameDomain : numNotSameDomain+1;
	        }
	        
	        if( anchorUrls.size() > 0) {
	        	urlOfAnchor = (numNotSameDomain/anchorUrls.size()*100) > 67 ? -1 : (numNotSameDomain/anchorUrls.size()*100) < 31 ? 1 : 0;
	        }else {
	        	urlOfAnchor = 1;
	        }
	        	
    		
		} catch (Exception e) {
			urlOfAnchor = 0;
		}
		
		System.out.println("URL_of_Anchor = " + urlOfAnchor + "\n");
		
		
		//---- LINKS IN TAGS
		

		try {
		
		Document doc = Jsoup.connect(url).get();

		Elements links = doc.select("link");
		Elements metas = doc.select("meta");
		Elements scripts = doc.select("script");
		double numNotSameDomain = 0;
		ArrayList<String> tagsUrl = new ArrayList<String>();
		
		for(Element e : links)
			tagsUrl.add(e.attr("href").trim());
		
		for(Element e : metas)
			tagsUrl.add(e.attr("content"));
		
		for(Element e : scripts) {
			
			if(e.data().contentEquals(""))
				tagsUrl.add(e.attr("src"));
			else
				tagsUrl.add(e.data());
		}
		
		for(String s : tagsUrl) {
			ArrayList<String> extractedUrls = extractUrls(s);
			for(String u : extractedUrls)
				numNotSameDomain = isSameDomain(url, u) ? numNotSameDomain : numNotSameDomain+1;
		}
		
		if(tagsUrl.size() > 0)
			linksInTags = (numNotSameDomain/tagsUrl.size() *100 < 17) ? 1 : (numNotSameDomain/tagsUrl.size() *100 > 81) ? -1 : 0;
		else
			linksInTags = 1;
		
		} catch (Exception e1) {
			linksInTags = 0;
		}
		
		System.out.println("Links_In_Tags = " + linksInTags + "\n");
		
		
		//---- SFH
		
		try {
			
			Document doc = Jsoup.connect(url).timeout(1000*1000).get();
			Elements forms = doc.select("form");
			ArrayList<String> tagUrls = new ArrayList<String>();
			
			for(Element f : forms) {
				
				if(!f.hasAttr("action") || f.attr("action").equals("about:blank") || f.attr("action").equals("")) {
					sfh = -1;
					break;
				}
				
				tagUrls.add(f.attr("action"));
			}
			
			if(sfh == 0) {
				
				if(tagUrls.size() > 0) {
					
					for(String s : tagUrls) {
						if (!isSameDomain(url, s)) {
							sfh = 0;
							break;
						}else
							sfh = 1;
					}
					
				}else
					sfh = 1;
			}	

		} catch (Exception e1) {
			sfh = 0;
		}
		
		System.out.println("SFH = " + sfh + "\n");
		
		
		//---- SUBMITTING TO EMAIL

		
		try {
			
			Document doc = Jsoup.connect(url).timeout(1000*1000).get();
			Elements forms = doc.select("form");
			
			for(Element e : forms) {
				
				if(e.hasAttr("action") && e.attr("action").startsWith("mailto:")) {
					submittingToEmail = -1;
					break;
				}else
					submittingToEmail = 1;
			
			}
			
		} catch (Exception e1) {
			submittingToEmail = -1;
		}

		System.out.println("Submitting_To_Email = " + submittingToEmail + "\n");
		
		
		//---- ABNORMAL URL
		
		URI uri = null;
		try {
			
			uri = new URI(url);
			String hostname = uri.getHost().trim();
			abnormalURL = (hostname == null) ? -1: (Character.isDigit(hostname.charAt(0)) == true) ? -1:1;

		} catch (Exception e) {
			abnormalURL = -1;
		}

		System.out.println("Abnormal_URL = " + abnormalURL + "\n");
		
		featuresToReturn[0] = requestURL;
		featuresToReturn[1] = urlOfAnchor;
		featuresToReturn[2] = linksInTags;
		featuresToReturn[3] = sfh;
		featuresToReturn[4] = submittingToEmail;
		featuresToReturn[5] =  abnormalURL;
		
		return featuresToReturn;
	}
	
	
	private static double[] getDomainFeatures(String url) {
		
		double[] featuresToReturn = new double[7];
		
		double googleIndex = -1;
		double webTraffic = 0;
		double ageOfDomain = -1;
		double dnsRecord = -1;
		double pageRank = -1;
		double linksPointingToPage = 0;
		double statisticalReport = -1;
		
		
		//------ AGE OF DOMAIN
		
		try {
			
			WhoisClient wh = new WhoisClient();
			wh.connect(WhoisClient.DEFAULT_HOST);
			String whoisData = wh.query(getDomainFromUrl(url));
			wh.disconnect(); 
			String st = whoisData.substring(whoisData.indexOf("Creation Date:")+14);
			String creationDate = st.substring(0,st.indexOf("Registry Expiry Date"));
			
			
			SimpleDateFormat parser = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	        parser.setTimeZone(TimeZone.getTimeZone("UTC"));
	        Date parsed = parser.parse(creationDate);
	        
	        Calendar cal = Calendar.getInstance();
	        cal.add(Calendar.MONTH, -6);

	        ageOfDomain = parsed.before(parser.parse(parser.format(cal.getTime()))) ? 1:-1;
	        
		}catch (Exception e) {
			ageOfDomain = -1;
		} 
		
		System.out.println("Age_Of_Domain = " + ageOfDomain + "\n");
		
		
		//----- DNS RECORD
		
		try {
			
			WhoisClient wh = new WhoisClient();
			wh.connect(WhoisClient.DEFAULT_HOST);

			String whoisData = wh.query(getDomainFromUrl(url));
			wh.disconnect();
			
			dnsRecord = whoisData.contains("Name Server:")? 1 : -1;
			
		} catch (Exception e1) {
			dnsRecord = -1;
		}
		
		System.out.println("Dns_Record = " + dnsRecord + "\n");
		
		
		//------- ALEXA ranking search : WEB TRAFFIC
		

				try {
					
					String domainName = getDomainFromUrl(url);
					
					URL searchUrl = new URL("https://www.alexa.com/siteinfo/" + domainName + "?ver=alpha&utm_expid=.NFDkwnQTSf2ZNn_fyyCLoQ.2&utm_referrer=https%3A%2F%2Fwww.alexa.com%2Fsiteinfo");
				
					HttpURLConnection conn = (HttpURLConnection) searchUrl.openConnection();
			        conn.setRequestMethod("GET");
			        conn.setRequestProperty("Accept", "application/json");
			        BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
			        
			        String output; 
			        String result="";

			        while ((output = br.readLine()) != null)
			        	result += output;
			        
			        String json = result.substring(result.indexOf("dataLayer.push(")+15);
			        json = json.substring(0,json.indexOf("</script>"));
			        json = json.substring(0, json.length()-4);
			        
			        JSONObject obj = new JSONObject(json);
			        int rankResult = obj.getJSONObject("siteinfo").getJSONObject("rank").getInt("global");
			        
			        webTraffic = rankResult == 0 ? -1: rankResult < 100000 ? 1 : 0;
			        
				} catch (Exception e) {
					webTraffic = -1;
				} 
				
		        System.out.println("Web_Traffic = " + webTraffic + "\n");
		
		        
		//----- PAGE RANK
		
			try {
					
				URL requestUrl = new URL("https://checkpagerank.net/index.php"); //1 request each 30 seconds

				HttpURLConnection con = (HttpURLConnection) requestUrl.openConnection();
				con.setRequestMethod("POST");
				con.setDoOutput(true);
				OutputStream os = con.getOutputStream();
				String params = "name=" + getDomainFromUrl(url);
				os.write(params.getBytes());
				os.flush();
				os.close();
				int responseCode = con.getResponseCode();
				
				if (responseCode == HttpURLConnection.HTTP_OK) {
					BufferedReader in = new BufferedReader(new InputStreamReader(
							con.getInputStream()));
					String inputLine;
					StringBuffer response = new StringBuffer();
					double rank = 0;
					
					while ((inputLine = in.readLine()) != null) {
						response.append(inputLine);
						//System.out.println(inputLine);
						if(inputLine.contains("<div><h2><b>Google PageRank:</b>")) {
							rank = Integer.parseInt(inputLine.substring(inputLine.indexOf("Google PageRank:")+46, inputLine.indexOf("/10</b>")));
							break;
						}
					}
					in.close();
					con.disconnect();

					//String res = response.toString();
					//double rank = Integer.parseInt(res.substring(res.indexOf("Google PageRank:")+46, res.indexOf("/10</b>")));

					pageRank = rank/10 < 0.2 ? -1 : 1;
				
				} else {
					pageRank = -1;
				}
				
				
				} catch (Exception e) {
					pageRank = -1;
				}
				
			System.out.println("Page_Rank = " + pageRank + "\n");
			
			
		//---- GOOGLE API for indexing search : GOOGLE INDEX
	    
		JSONObject objJ = null;
		try {
		
			BufferedReader buf = new BufferedReader(new FileReader("google_api_key")); //100 request per day
			String GOOGLE_API_KEY = buf.readLine();
			buf.close();
		  
		  URL searchUrl = new URL(
	                "https://www.googleapis.com/customsearch/v1?key=" + GOOGLE_API_KEY + "&cx=013036536707430787589:_pqjad5hr1a&q=site:" + url + "&alt=json");
	        HttpURLConnection conn = (HttpURLConnection) searchUrl.openConnection();
	        conn.setRequestMethod("GET");
	        conn.setRequestProperty("Accept", "application/json");

			BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));


	        String output; 
	        String result = "";

			while ((output = br.readLine()) != null)
					result += output;
			
			conn.disconnect();
			//System.out.println(result);
	         objJ = new JSONObject(result);
	        
	        //System.out.println(obj.toString());
	        	
	        int googleResults = Integer.parseInt(objJ.getJSONObject("queries").getJSONArray("request").getJSONObject(0).getString("totalResults"));
	        
	        googleIndex = googleResults == 0 ? -1:1;
	        
		}catch(Exception e) {
			googleIndex = -1;
		}
		
		System.out.println("Google_Index = " + googleIndex + "\n");
		
	     
		//---- LINKS POINTING TO PAGE
		
		/*try {
			
			URL searchUrl = new URL(
			        "https://www.googleapis.com/customsearch/v1?key=" + GOOGLE_API_KEY + "&cx=013036536707430787589:_pqjad5hr1a&q=site:" + url + "&alt=json");

	        HttpURLConnection conn = (HttpURLConnection) searchUrl.openConnection();
	        conn.setRequestMethod("GET");
	        conn.setRequestProperty("Accept", "application/json");
	
			BufferedReader br = new BufferedReader(new InputStreamReader((conn.getInputStream())));
	
	
	        String output; 
	        String result="";
	
			while ((output = br.readLine()) != null)
					result += output;
				
	
	        JSONObject obj = new JSONObject(result);
	        conn.disconnect();
		 */
		try {
			
		   int numLinksPointing = 0;
		   
		   for(int i = 0; i<10; ++i) {
			   String obtainedLink = objJ.getJSONArray("items").getJSONObject(i).getString("link");
			   try {
				numLinksPointing = getDomainFromUrl(obtainedLink).equals(getDomainFromUrl(url)) ? numLinksPointing + 1 : numLinksPointing;
			   } catch (URISyntaxException e) {
			   }
		   }
		   
		   linksPointingToPage = numLinksPointing == 0 ? -1 : numLinksPointing > 2 ? 1 : 0;
		
		}catch (Exception e) {
			linksPointingToPage = -1;
		}
		
		
		System.out.println("Links_Pointing_To_Page = " + linksPointingToPage + "\n");
		
		
		//----- STATISTICAL REPORT
		
		try {
			
			URL phishtankUrl = new URL("http://checkurl.phishtank.com/checkurl/");

			HttpURLConnection con = (HttpURLConnection) phishtankUrl.openConnection();
			con.setRequestMethod("POST");
			con.setDoOutput(true);
			OutputStream os = con.getOutputStream();
			String params = "format=json&url=" + url;
			os.write(params.getBytes());
			os.flush();
			os.close();
			int responseCode = con.getResponseCode();
			
			if (responseCode == HttpURLConnection.HTTP_OK) {
				BufferedReader in = new BufferedReader(new InputStreamReader(
						con.getInputStream()));
				String inputLine;
				StringBuffer response = new StringBuffer();
				String re = "";
				while ((inputLine = in.readLine()) != null) {
					response.append(inputLine);
					re += inputLine;
				}
				in.close();
				con.disconnect();
	
		        JSONObject obj = new JSONObject(re);
		       
		        boolean in_db = obj.getJSONObject("results").getBoolean("in_database");
		        if(in_db == false) {
		        	statisticalReport = 1;
		        }else {
		        	
		        	 boolean verified = obj.getJSONObject("results").getBoolean("verified");
		        	 if(verified == true) {
		        		 
		        		 boolean valid = obj.getJSONObject("results").getBoolean("valid");
		        		 statisticalReport = valid == false ? 1 : -1;
		        		 
		        	 }else {
		        		 
		        		 statisticalReport = -1;
		        	 }
		        }
		      
			
			}else
				statisticalReport = 1;
		
		
		} catch (Exception e) {
			statisticalReport = 1;
		}
		
		System.out.println("Statistical_Report = " + statisticalReport + "\n");
		
		featuresToReturn[0] = ageOfDomain;
		featuresToReturn[1] = dnsRecord;
		featuresToReturn[2] = webTraffic;
		featuresToReturn[3] = pageRank;
		featuresToReturn[4] = googleIndex;
		featuresToReturn[5] = linksPointingToPage;
		featuresToReturn[6] = statisticalReport;
		
		return featuresToReturn;
		
	}
	
	private static double[] getDocumentFeatures(String url) {
		
		double[] featuresToReturn = new double[5];
		
		double websiteForwarding = 0;
		double statusBarCustomization = -1;
		double disablingRightClick = -1;
		double usingPopUpWindow = -1;
		double iFRameRedirection = -1;
		
		//----- WEBSITE FORWARDING
		
		int count = 0;
		
		try {

			URL site = new URL(url);
			HttpURLConnection connection = (HttpURLConnection)site.openConnection();
			connection.connect();
			int returnCode = connection.getResponseCode();
			
			while(returnCode == HttpURLConnection.HTTP_MOVED_PERM || returnCode == HttpURLConnection.HTTP_MOVED_TEMP || returnCode == HttpURLConnection.HTTP_SEE_OTHER){
			 count++;
			 String location = connection.getHeaderField("Location");
			 connection = (HttpURLConnection) new URL(location).openConnection();
			 returnCode = connection.getResponseCode();
			}
			
		} catch (Exception e) {
			
		}
		
		websiteForwarding = (count <= 1) ? 1 : 0;
		System.out.println("Redirect = " + websiteForwarding + "\n");
		
		//----- STATUSBAR CUSTOMIZATION
		

		try {
			
			Document doc = Jsoup.connect(url).get();
	
			Elements elements = doc.getElementsByAttribute("onmouseover");
			if(elements.size() > 0) {
				
				for(Element e : elements) {
					String javascriptText = e.attr("onmouseover");
					if(javascriptText.contains("window.status=") || javascriptText.contains("window.status =")) {
						statusBarCustomization = -1;
						break;
					}else
						statusBarCustomization = 1;
						
				}	
				
			}else
				statusBarCustomization = 1;
		
		} catch (Exception e) {
			statusBarCustomization = 1;
		}
		
		System.out.println("on_mouseover = " + statusBarCustomization + "\n");
		
		
		//----- RIGHT CLICK
		
		try {
			
			Document doc = Jsoup.connect(url).get();

			Elements elements = doc.getElementsByAttribute("oncontextmenu");
			if(elements.size() > 0) {
				
				for(Element e : elements) {
					if(e.attr("oncontextmenu").contains("return false")) {
						disablingRightClick = -1;
						break;
					}else
						disablingRightClick = 1;
						
				}
				
			}else
				disablingRightClick = 1;
			
		} catch (Exception e) {
			disablingRightClick = 1;
		}
		
		System.out.println("Right_Click = " + disablingRightClick + "\n");
		
		
		//----- POPUP WINDOW
		
		try {
			
			Document doc = Jsoup.connect(url).get();

			if(doc.data().contains("prompt("))
				usingPopUpWindow = -1;
			else
				usingPopUpWindow = 1;
		
		} catch (Exception e) {
			usingPopUpWindow = 1;
			
		}
		
		System.out.println("popUpWindow = " + usingPopUpWindow + "\n");
		
		
		//----- IFRAME
		
		try {
			
			Document doc = Jsoup.connect(url).get();

			Elements iframes = doc.select("iframe");
			if(iframes.size() > 0)
				iFRameRedirection = -1;
			else
				iFRameRedirection = 1;
		
		} catch (Exception e) {
			iFRameRedirection = 1;
		}
		
		System.out.println("Iframe = " + iFRameRedirection + "\n");
		
		
		featuresToReturn[0] = websiteForwarding;
		featuresToReturn[1] = statusBarCustomization;
		featuresToReturn[2] = disablingRightClick;
		featuresToReturn[3] = usingPopUpWindow;
		featuresToReturn[4] = iFRameRedirection;

		return featuresToReturn;
	}
	
	
	public static String getDomainFromUrl(String url) throws URISyntaxException {
		
		String fullDomain = null;
		try{
			
			InternetDomainName fullDomainName = InternetDomainName.from(new URI(url).getHost());
			fullDomain = fullDomainName.topPrivateDomain().toString();;
			
		}catch(Exception e) {
			fullDomain = new URI(url).getHost();
		}
		
	    return fullDomain;
	}
	
	public static boolean isSameDomain(String originalUrl, String urlToCheck) {
		
		boolean toReturn = false;
		
    	String originalHost = null;
    	
		try {
			originalHost = new URI(originalUrl).getHost();
		} catch (URISyntaxException e1) {
			toReturn= false;
			return toReturn;
		}
		
		if(originalHost != null) {
			
			String hostname;
			try {
				hostname = new URI(urlToCheck).getHost();

	    	
		    	if(hostname != null) {
		    		
		    		 if( getDomainFromUrl(urlToCheck).equals(getDomainFromUrl(originalUrl)) ) {
		    				 toReturn = true;
	
		    				// System.out.println("Preso: hostname match");
		    		 }
		    		 
		    	}else {
		    		
		    		if(urlToCheck.startsWith("/") && !urlToCheck.startsWith("//")) {
		    			toReturn =  true;
		    			//System.out.println("Preso: hostname null e comincia con /");
		    			
		    		}else {
		    			
		    		
		        		String[] temp = urlToCheck.split("\\.");
		        		
		        		if(temp.length > 1) {
		        			
		        			String ext = temp[temp.length-1];
		        			String[] acceptedExtensions = {"php", "html", "js", "mp4", "webm", "ogg", "mpeg", "wav", "jpg", "png", "gif", "ico"};
		        			if(Arrays.asList(acceptedExtensions).contains(ext)) {
		        				toReturn = true;
		        				//System.out.println("Preso: hostname null ma pagina con estensione buona " + ext);
		        			}
		        		}
		    		}
		    	}
	    	
			} catch (URISyntaxException e) {
				return false;
			}
		}

		return toReturn;
		
	}
	
	public static  ArrayList<String> extractUrls(String text)
	{
	    ArrayList<String> containedUrls = new ArrayList<String>();
	    text = text.replaceAll("\\\\", "");
	    String urlRegex = "((https?|ftp|gopher|telnet|file):((//)|(\\\\))+[\\w\\d:#@%/;$()~_?\\+-=\\\\\\.&]*)";
	    Pattern pattern = Pattern.compile(urlRegex, Pattern.CASE_INSENSITIVE);
	    Matcher urlMatcher = pattern.matcher(text);

	    while (urlMatcher.find())
	    {
	        containedUrls.add(text.substring(urlMatcher.start(0),
	                urlMatcher.end(0)));
	    }

	    return containedUrls;
	}
	
}
