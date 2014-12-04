/* This file is part of the University of Cambridge Web Authentication
 * System Java Toolkit
 *
 * Copyright 2005,2014 University of Cambridge
 *
 * This toolkit is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * The toolkit is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this toolkit; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 *
 * $Id: WebauthResponse.java,v 1.10 2005/03/31 15:09:19 jw35 Exp $
 */

package uk.ac.cam.ucs.webauth;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.TimeZone;

/**
 * Represents an authentication response message.
 * 
 * @see <a href="http://raven.cam.ac.uk/project/waa2wls-protocol.txt">The
 *      Cambridge Web Authentication System: WAA->WLS communication protocol</a>
 * 
 * @version $Revision: 1.10 $ $Date: 2005/03/31 15:09:19 $
 */

public class WebauthResponse implements Serializable {
  
  private static final long serialVersionUID = 7637447443083877684L;
  
  // Fields used in protocol versions 1 and 2
  private static final String[] FIELD_NAMES_12 = {
      "ver", "status", "msg", "issue", "id", "url", "principal", "auth", "sso", "life", "params",
      "kid", "sig"};

  // Fields used in protocol version 3
  private static final String[] FIELD_NAMES_3 = {
      "ver", "status", "msg", "issue", "id", "url", "principal", "ptags", "auth", "sso", "life",
      "params", "kid", "sig"};

	private static final char RESPONSE_SEP = '!';
	private static final String DATE_FORMAT = "yyyyMMdd'T'HHmmss'Z'";

	private HashMap<String,String> data;

	private String[] fieldNames;
	private int nFields;
	private String rawData = "";
	private String token;

	/**
	 * Status code representing successfull authentication
	 */

	public static final int SUCCESS = 200;

	/**
	 * Status code indicating that the user actively abandoned the
	 * authentication process by selecting a cancel button or similar process.
	 * Note that users can equally abandoned the authentication process by
	 * directing their browser elsewhere after an authentication request in
	 * which case no response will be forthcoming.
	 */

	public static final int CANCELED = 410;

	/**
	 * Status code indicating that the authentication server does not support
	 * any of the authentication types specified in the 'aauth' parameter of the
	 * authentication request.
	 */

	public static final int NO_COMMON_AUTH = 510;

	/**
	 * Status code indicating that the authentication server does not support
	 * the version of the protocol used in the authentication response. This
	 * status code will only ever be sent in a response with the 'ver' field'
	 * set to 1.
	 */

	public static final int BAD_VERSION = 520;

	/**
	 * Status code indicating tha tthere was a problem decoding the request
	 * parameters that is not covered by a more specific status - perhaps an
	 * unrecognised parameter.
	 */

	public static final int REQUEST_ERROR = 530;

	/**
	 * Status code indicating that a request specified 'iact' as 'no' but either
	 * the user is not currently identified to the WLS or the user has asked to
	 * be notified before responses that identify him/her are issued.
	 */

	public static final int IACT_REQUIRED = 540;

	// public static final int SKEW_TOO_LARGE = 550;

	/**
	 * Status code indicating that this application is not authorised to use the
	 * targeted authentication server.
	 */

	public static final int UNAUTHORIZED = 560;

	/**
	 * Status code indicating that the authentication server declines to provide
	 * authentication services on this occasion.
	 */

	public static final int DECLINED = 570;

	/**
	 * Returns a String description of a String status code
	 * 
	 * @param status
	 *            String status code
	 * 
	 * @return text description
	 */

	public static String statusString(String status) {
		if (status.equals("200")) {
			return "OK";
		} else if (status.equals("410")) {
			return "Authentication cancelled at user's request";
		} else if (status.equals("510")) {
			return "No mutually acceptable types of authentication available";
		} else if (status.equals("520")) {
			return "Unsupported authentication protocol version";
		} else if (status.equals("530")) {
			return "Parameter error in authentication request";
		} else if (status.equals("540")) {
			return "Interaction with the user would be required";
			// } else if (status.equals("550")) {
			// return "Web server and authentication server clocks out of sync";
		} else if (status.equals("560")) {
			return "Web server not authorised to use "
					+ "the authentication service";
		} else if (status.equals("570")) {
			return "Operation declined by the authentication service";
		} else {
			return "Unrecognised status code: " + status;
		}
	}

	/**
	 * Returns a String description of a int status code
	 * 
	 * @param status
	 *            int status code
	 * 
	 * @return text description
	 */

	public static String statusString(int status) {
		return statusString(String.valueOf(status));
	}

	/**
	 * Constructs a new WebauthResponse object from a string representation of a
	 * response. This method does not attempt to validate the response message
	 * it is parsing (see {@link WebauthValidator}).
	 * 
	 * @param token
	 *            a Response message in string form 
	 * @throws WebauthException 
	 */

	public WebauthResponse(String token) throws WebauthException {

		String[] value = Util.split(RESPONSE_SEP, token);
		this.token = token;

    // The first field should always be the protocol version number
    int version;

    if (value == null || value.length < 1 || value[0].length() == 0)
      throw new WebauthException("Error: response does not specify a protocol version");

    try {
      version = Integer.parseInt(value[0]);
      if (version <= 0)
        throw new WebauthException("Error: invalid protocol version - " + version);
    } catch (NumberFormatException e) {
      throw new WebauthException("Error: protocol version is not a valid integer", e);
    }

    fieldNames = version < 3 ? FIELD_NAMES_12 : FIELD_NAMES_3;
    nFields = (value.length < fieldNames.length) ? value.length : fieldNames.length;
		data = new HashMap<String,String>(nFields);
		for (int i = 0; i < nFields; ++i) {
			try {
				data.put(fieldNames[i],URLDecoder.decode(value[i],"UTF-8"));
			} catch (UnsupportedEncodingException e) {
				// Shouldn't happen
				throw new Error("Unable to use encoding UTF-8");
			}
		}

		int ultimate = token.lastIndexOf(RESPONSE_SEP);
		int penultimate = token.lastIndexOf(RESPONSE_SEP, ultimate - 1);
		if (penultimate > 0)
			rawData = token.substring(0, penultimate);

	}

	/* public methods to retrieve data */

	/**
	 * Returns the number of fields found in the response
	 * 
	 * @return the number of fields
	 */

	public int length() {
		return nFields;
	}

	/**
	 * Returns a java.util.Iterator of all the field names that this response
	 * contains.
	 * 
	 * @return an Iterator of all the field names
	 */

	public Iterator<String> getFieldNames() {
		return data.keySet().iterator();
	}

	/**
	 * Returns the string value of the specified field from this response
	 * 
	 * @param field
	 *            a field name from the response
	 * 
	 * @return the string value of the specified field; or "" if the specified
	 *         field was not present in the response.
	 */

	public String get(String field) {
		if (field == null || data.get(field) == null)
			return "";
		return data.get(field);
	}

	/**
	 * Returns an integer value expressing the value of the specified field from
	 * this response
	 * 
	 * @param field
	 *            a field name from the response
	 * 
	 * @return an integer expressing the value of the response field or -1 if
	 *         the response doesn't have a field of this name or it was empty
	 * 
	 * @throws WebauthException
	 *             if the field can't be converted into an int
	 * 
	 */

	public int getInt(String field) throws WebauthException {
		if (get(field).equals(""))
			return -1;
		try {
			return Integer.parseInt(get(field));
		} catch (NumberFormatException e) {
			throw new WebauthException("Error converting response field '"
					+ field + "' to an integer: " + e.getMessage());
		}
	}

	/**
	 * Returns the value of the specified response field as a long value that
	 * represents a Date object. The date is returned as the number of
	 * milliseconds since January 1, 1970 GMT.
	 * 
	 * @param field
	 *            a field name from the response
	 * 
	 * @return a long value representing the date specified in the field
	 *         expressed as the number of milliseconds since January 1, 1970
	 *         GMT, or -1 if the response doesn't have a field of this name or
	 *         it was empty
	 * 
	 * @throws WebauthException
	 *             if the field can't be converted into an date
	 * 
	 */

	public long getDate(String field) throws WebauthException {
		if (get(field).equals(""))
			return -1;
		try {
			SimpleDateFormat format = new SimpleDateFormat(DATE_FORMAT);
			format.setTimeZone(TimeZone.getTimeZone("GMT+00:00"));
			return format.parse(get(field)).getTime();
		} catch (ParseException e) {
			throw new WebauthException("Error converting resposne field '"
					+ field + "' as a date: " + e.getMessage());
		}
	}

	/**
	 * Returns a java.util.collection containing the comma-seperated strings
	 * from the specified field from this response
	 * 
	 * @param field
	 *            a field name from the response
	 * 
	 * @return a java.utils.Collection containing the comma-seperated strings
	 *         from the specified response field. Returns an empty collection if
	 *         the response doesn't have a field of this name or it was empty
	 */

	public Collection<String> getColl(String field) {
		HashSet<String> set = new HashSet<String>();
		for (String item : Util.split(',',get(field))) {
			set.add(item.trim());
		}
		return set;
	}

	/**
	 * Returns the raw data from this response, less the key-id and signature.
	 * This is exactly the data over which the signature should be calculated.
	 * 
	 * @return a string representing the raw data, or an empty string if there
	 *         was no raw data
	 */

	public String getRawData() {
		return rawData;
  }

  /**
   * Returns the original Raven token that this response object was created from.
   * 
   * @return the response string from the Raven server.
   */
  public String getToken() {
    return token;
  }

	/**
	 * Returns a human-readable string representation this response mesage
	 * 
	 * @return string representation of this response
	 */

	@Override
	public String toString() {
		StringBuffer str = new StringBuffer("Webauth response: ");
		for (int i = 0; i < fieldNames.length; ++i) {
			if (i != 0)
				str.append(", ");
			str.append(fieldNames[i] + ": " + get(fieldNames[i]));
		}
		return str.toString();
	}

  /**
   * Gets a parameter value stored within the params field.
   * 
   * Returns: The parameter value if found. An empty string if the parameter name exists without a
   * value. Null if the parameter does not exist.
   */
  String getParam(String paramName) {
    if (paramName == null || paramName.length() == 0)
      return null;

    Collection<String> params = getColl("params");
    if (params == null)
      return null;

    // remove any existing method
    for (String s : params) {

      String[] tokens = s.split("=", 2);

      if (paramName.equals(tokens[0])) {
        if (tokens.length >= 2)
          return tokens[1];
        else
          return "";// parameter present but no value
      }
    }

    return null;
  }

}
