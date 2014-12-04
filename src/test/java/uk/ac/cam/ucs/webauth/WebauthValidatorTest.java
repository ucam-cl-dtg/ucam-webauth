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
 * $Id: WebauthValidatorTest.java,v 1.9 2005/03/31 15:06:55 jw35 Exp $
 *
 */

package uk.ac.cam.ucs.webauth;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.util.TimeZone;

import junit.framework.TestCase;

/**
 * Test cases for the webauth protocol.
 * 
 * The protocol is documented at: 
 * 
 *   http://raven.cam.ac.uk/project/waa2wls-protocol.txt
 * 
 * Note: Below are many static-final webauth response messages. The following
 * Raven debug page is useful for creating additional responses:
 * 
 *   http://raven.cam.ac.uk/test.html
 *   
 */

public class WebauthValidatorTest extends TestCase {

    private static int TEST_TIMEOUT = 30000;
   // private static int TEST_MAX_SKEW = 0;

  /** response contains: auth=pwd */
  private static final String RESPONSE_V3_FIRSTHAND =
      "3!200!!20141110T150922Z!1415632162-15831-14!http://raven.cam.ac.uk/d"
          + "ebug.html!pms52!current!!pwd!42298!!2!vbyiHj1hqKxXW4n3gOXCagoBuJqb-7"
          + "TsRQUSo0S-SyjSlGyu7OJxsEr9-b1765AzLZD7eK1kjbUcnn0XCa.mrwshZgsq9nVfq-"
          + "ZGoWFX7t1cOyQDhx3duI2jRB7PvA4pppfULQpBnCYa5hp03a4E.dGiOctVf6I6xW6S3E"
          + "5uMSk_";

    private static final String RESPONSE_V2_FIRSTHAND = 
	"2!200!!20050317T151310Z!1111072390-26663-9!http://raven.cam.ac.uk/d" +
	"ebug.html!jw35!pwd!!36000!For babies!2!r9LDRfDhqaOXLWo3ERATEhzCsRFv" +
	"PDmRP2krjGjUylpkh9rdnK1knnf1z8P4JWDVQxsMKilnXfPZ-D9G-arghDd-Hgr9JTC" +
	"gnbttwikvL.yYAHvUCnhBY75QCRmBPZ1iQQcKdh2gzxX-HsJhmZ4uTn0vce4IlLFdQL" +
	"CbALj1nqw_";

  /** response contains: auth= sso=pwd */
  private static final String RESPONSE_V3_SSO =
      "3!200!!20141110T164620Z!1415637980-22212-8!http://raven.cam.ac.uk/d"
          + "ebug.html!pms52!current!!pwd!36480!!2!vWv9FKPhVXJw-lxuHJEBBM7j3F30j"
          + "isxy1FIgJw-LL1Vf6ZNKWSmdAaBaJsKyjMT80UZXhoSDyGP8iE1TDFz71P-r2XjvKl4"
          + "E8NHfKUUyXpDdI-JS97LVOEwCOivYmuRCI0iePevxxUku11-VlPPTv8qKZnHJG40TPI"
          + "UKU80VuM_";

    private static final String RESPONSE_V2_SSO =
	"2!200!!20050317T151424Z!1111072462-26473-5!http://raven.cam.ac.uk/d" +
	"ebug.html!jw35!!pwd!35928!For babies!2!aCwEktN6X7A-.mloMNOhsfaMbsgM" +
	"z9TxpZ2D9yLt-0XMP8K-9VKttn1Ot.-dkpoEE2TbXt0mJE5y4udjv-Qo4EjtaZxTcUB" +
	"lqaRwFcZGR3C2GoQeUWQaHHJdvRi2MwglnbTP6m7sT-o6Xlvnt3RcTgf-ncrkdFN.vN" +
	"ShVM1RhyU_";

    private static final String RESPONSE_V1 =
	"1!200!!20050317T151538Z!1111072536-26473-6!http://raven.cam.ac.uk/d" +
	"ebug.html!jw35!!pwd!35854!For babies!2!Xmm01Vu95g3t2iKCF.QkrTOCEkfz" +
	"QWpEsC90u5s8o5o9EYrrUljMAQMo0S-wxpdH4zXQWRfeS.rjk4-YWEbcr1qjzKm14.b" +
	"6iYP6rEagaHK1CCkL-V.8lUzWFjB3MacvJtfu1nP0-pw.kzP6ERIfMEYMEW37aReRSt" +
	"0LEnDJkO4_";

    private static final String RESPONSE_ERROR =
	"1!530!Missing required parameter 'ver'!20050317T151628Z!1111072588-" +
	"26568-7!http://raven.cam.ac.uk/debug.html!!!!!!2!ZUcFzGfEPyVhYqHYK9" +
	"gDfewP6xSOKNvdOcAp3ZpzGoDAmY1eG704aw1aDTOh6nTYtZAoGNqio33CCGWT29fjY" +
	"10phtSEe8xCNP9WgpohOze9SOYUXJ10uuVRXBXE.1DCiCPZxUODZPEaeOv8P0zgm3Jf" +
	"RsVdDy9SnDjFvQQ43O8_";

    private static final String RESPONSE_SUMMER = 
        "2!200!!20050331T145628Z!1112280988-1756-8!http://raven.cam.ac.uk/de" +
	"bug.html!jw35!pwd!!36000!!2!EpqdT4YZLfn-YtE8QA2bg0i1rnAXO9v5dTjiFgD" +
	"k9.C5XJ99D4KR9WOZniHzkaE79vSLeW-OqtM1Up6RXXap.1hWLH3Mk5ZKhulh1KSRE3" +
	"b2raTUqwx5smqnNVGgY0mA9VSTpGM4mJ7rGm5Hkh1aDsOSNiQ0XL6sm8EwsfcKoSI_";

    // The signatures on the following won't validate

    private static final String RESPONSE_FORGED = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw99!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String MISS_VER = 
	"!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";
    
    private static final String BAD_VER = 
	"A!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String MISS_STATUS = 
	"2!!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";
    
    private static final String SMALL_STATUS = 
	"2!1!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";
    
    private static final String MISS_ID = 
	"2!200!!20050314T140111Z!!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String MISS_URL = 
	"2!200!!20050314T140111Z!1110808871-12726-166!" +
	"!jw35!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String MISS_PRINCIPAL = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!!pwd!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String NO_AUTH_SSO = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!!!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";
    
    private static final String BAD_AUTH_SSO = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pw!pw!36000!Foo babies!2!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String MISS_KID = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String BAD_KID = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!3!VB4vcoeQSln6SKJGT7RauhLna" +
	"aVmNBtWZ8Ra5tzYv0-0GRNHBxrZxQK9SNwg0lw3eV6SPyWbDJwjSlgNAh9FvOVzxjOx" +
	"C30SgS8802dPjqnratjAKDqZBfBv004pslSdWsoE-CiHfAXAMUDzE9I.TH-RCKkqtMq" +
	"XwoRn4f.lXtU_";

    private static final String MISS_SIG = 
	"2!200!!20050314T140111Z!1110808871-12726-166!http://raven.cam.ac.u" +
	"k/debug.html!jw35!pwd!!36000!Foo babies!2!";


	private WebauthRequest request;
  private WebauthResponse response_v3_firsthand, response_v2_firsthand,
      response_v2_sso, response_v1, response_error, response_forged, response_summer;
  private long response_v3_firsthand_date, response_v2_firsthand_date,
      response_v2_sso_date, response_v1_date, response_error_date, response_forged_date,
      response_summer_date;
	private WebauthValidator validator;

	// ----------------------------------------------------------- Housekeeping

	public static void main(String args[]) {
		junit.textui.TestRunner.run(WebauthValidatorTest.class);
	}

	// --------------------------------------------------------------- Fixtures

	@Override
	protected void setUp() throws WebauthException, MalformedURLException,
			ParseException, KeyStoreException, FileNotFoundException,
			IOException, NoSuchAlgorithmException, CertificateException {

		// These tests fail if done not in the Europe/London timezone
		TimeZone.setDefault(TimeZone.getTimeZone("Europe/London"));

		// A request

		request = new WebauthRequest();
		request.set("ver", 2);
		request.set("url", "http://raven.cam.ac.uk/debug.html");

		// Some responses

    response_v3_firsthand = new WebauthResponse(RESPONSE_V3_FIRSTHAND);
    response_v3_firsthand_date = response_v3_firsthand.getDate("issue");

		response_v2_firsthand = new WebauthResponse(RESPONSE_V2_FIRSTHAND);
		response_v2_firsthand_date = response_v2_firsthand.getDate("issue");

		response_v2_sso = new WebauthResponse(RESPONSE_V2_SSO);
		response_v2_sso_date = response_v2_sso.getDate("issue");

		response_v1 = new WebauthResponse(RESPONSE_V1);
		response_v1_date = response_v1.getDate("issue");

		response_error = new WebauthResponse(RESPONSE_ERROR);
		response_error_date = response_error.getDate("issue");

		response_forged = new WebauthResponse(RESPONSE_FORGED);
		response_forged_date = response_forged.getDate("issue");

		response_summer = new WebauthResponse(RESPONSE_SUMMER);
		response_summer_date = response_summer.getDate("issue");

		// A key store and a validator using it

		KeyStore ks = KeyStore.getInstance("JKS");
		ks.load(this.getClass().getResourceAsStream("/keystore"),
				"keystore password".toCharArray());
		validator = new WebauthValidator(ks);

	}

	@Override
	protected void tearDown() {
		TimeZone.setDefault(null);// Undo the change we did in setup (hopefully)
	}

	// ----------------------------------------------------------------- Tests

	// Note that passing WebauthResponse.get("ssue") as a date to
	// validate is normally a silly thing to do (you want to pass the
	// current date/time) but it's useful here becasue it means we can
	// run tests with response messages that were actually created
	// some time ago...

	public void testV2Date() {
		assertEquals(response_v2_firsthand_date, 1111072390000L);
	}

	public void testSummerDate() {
		assertEquals(response_summer_date, 1112280988000L);
	}

	// Basic tests - accept a valid response, reject a forged one

	public void testDefaults() {
		assertEquals(TEST_TIMEOUT, validator.getTimeout());
		assertEquals(500, validator.getMaxSkew());
		assertEquals("webauth-pubkey", validator.getKeyPrefix());
	}

	public void testBasic() throws WebauthException {

    request.set("ver", 2);
    validator.validate(request, response_v2_firsthand, response_v2_firsthand_date);

    request.set("ver", 3);
    validator.validate(request, response_v3_firsthand, response_v3_firsthand_date);
	}

	public void testForged() {
		try {
			validator.validate(request, response_forged, response_forged_date);
			fail("Didn't detect forged response");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Unable to verify response signature", e.toString());
		}
	}

	// Various parameter errors

	public void testMissVer() {
		try {
		  WebauthResponse r = new WebauthResponse(MISS_VER);
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect missing protocol version number");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Error: response does not specify a protocol version",
					e.toString());
		}
	}

	public void testBadVer() {
		try {
		  WebauthResponse r = new WebauthResponse(BAD_VER);
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect bad protocol version number");
		} catch (WebauthException e) {
			assertTrue(true);
		}
	}

	public void testMissStatus() throws WebauthException {
		WebauthResponse r = new WebauthResponse(MISS_STATUS);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect missing status code");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Status code missing from response", e.toString());
		}
	}

	public void testSmallStatus() throws WebauthException {
		WebauthResponse r = new WebauthResponse(SMALL_STATUS);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect out of range status code");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Unrecognised status code: 1", e.toString());
		}
	}

	public void testMissID() throws WebauthException {
		WebauthResponse r = new WebauthResponse(MISS_ID);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("didn't detect missing response ID");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response ID missing", e.toString());
		}
	}

	public void testMissURL() throws WebauthException {
		WebauthResponse r = new WebauthResponse(MISS_URL);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("didn't detect missing response URL");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "URL missing from response", e.toString());
		}
	}

	public void testMissPrincipal() throws WebauthException {
		WebauthResponse r = new WebauthResponse(MISS_PRINCIPAL);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("didn't detect missing principal in status 200 response");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Principal missing from status 200 response",
					e.toString());
		}
	}

	public void testNoAuthSSO() throws WebauthException {
		WebauthResponse r = new WebauthResponse(NO_AUTH_SSO);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("didn't spot missing first-hand and SSO tokens in response");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "No authentication type found in status 200 response",
					e.toString());
		}
	}

	public void testBadAuthSSO() throws WebauthException {
		WebauthResponse r = new WebauthResponse(BAD_AUTH_SSO);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("didn't detect both first-hand and SSO tokens in response");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Both first-hand and SSO auth tokens found "
					+ "in response", e.toString());
		}
	}

	public void testMissKId() throws WebauthException {
		WebauthResponse r = new WebauthResponse(MISS_KID);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect missing KId in status 200 response");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "KeyID and/or signature missing from status "
					+ "200 response", e.toString());
		}
	}

	public void testBadKId() throws WebauthException {
		WebauthResponse r = new WebauthResponse(BAD_KID);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect invalid KId");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Failed to retrieve a key with alias "
					+ "webauth-pubkey3 from the key store", e.toString());
		}
	}

	public void testMissSig() throws WebauthException {
		WebauthResponse r = new WebauthResponse(MISS_SIG);
		try {
			validator.validate(request, r, r.getDate("issue"));
			fail("Didn't detect missing sig in status 200 response");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "KeyID and/or signature missing from status "
					+ "200 response", e.toString());
		}
	}

	// Test protocol version handling

	public void testVer() {
		request.set("ver", 1);
		try {
			validator.validate(request, response_v2_firsthand,
					response_v2_firsthand_date);
			fail("Didn't detect unacceptable version number");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Unacceptable protocol version (2) in response",
					e.toString());
		}
	}

	// Test URL matching

  public void testURL() throws WebauthException {

    // request url starts as: http://raven.cam.ac.uk/debug.html
    // response_v2_firsthand has the same url: http://raven.cam.ac.uk/debug.html

    /*
     * Test v1 protocol.
     */
    request.set("ver", 1);
    request.set("url", "http://raven.cam.ac.uk/debug.html");
    validator.validate(request, response_v1, response_v1_date);

    // in v1, the response url should start with the request url.

    request.set("url", "http://raven.cam.ac.uk/");
    validator.validate(request, response_v1, response_v1_date);

    // check for shorter response.
    request.set("url", "http://raven.cam.ac.uk/debug.htmlextra");
    try {
      validator.validate(request, response_v1, response_v1_date);
      fail("Didn't detect short URL in response");
    } catch (WebauthException e) {
      // correct response
    }
    // Check behaviour of query string.
    // Same host and path should validate, query string can change.
    request.set("url", "http://raven.cam.ac.uk/debug.html?foo=bar");
    validator.validate(request, response_v1, response_v1_date);

    // check for different url
    request.set("url", "http://a.b/c.d/");
    try {
      validator.validate(request, response_v1, response_v1_date);
      fail("Didn't detect different URL in response");
    } catch (WebauthException e) {
      // correct response
    }

    /*
     * Test v2 protocol.
     */

    request.set("ver", 2);

    request.set("url", "http://raven.cam.ac.uk/debug.html");
    validator.validate(request, response_v2_firsthand, response_v2_firsthand_date);

    // in v2, the response url should be an exact match of the request url.
    request.set("url", "http://raven.cam.ac.uk/");
    try {
      validator.validate(request, response_v2_firsthand, response_v2_firsthand_date);
      fail("Didn't detect different URL in response");
    } catch (WebauthException e) { /* correct response */
    }

    // check adding a query string fails.
    request.set("url", "http://raven.cam.ac.uk/debug.html?foo=bar");
    try {
      validator.validate(request, response_v2_firsthand, response_v2_firsthand_date);
      fail("Didn't detect different URL in response");
    } catch (WebauthException e) { /* correct response */
    }

    // check for different url
    request.set("url", "http://a.b/c.d/");
    try {
      validator.validate(request, response_v2_firsthand, response_v2_firsthand_date);
      fail("Didn't detect different URL in response");
    } catch (WebauthException e) { /* correct response */
    }

  }

	// Test status code handling

	public void testStatus() {
		try {
			validator.validate(request, response_error, response_error_date);
			fail("Didn't detect non-200 status");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Parameter error in authentication request: "
					+ "Missing required parameter 'ver'", e.toString());
		}
	}

	// Timeout handling - edge case with zero timeout, zero skew

	public void testZeroTimeout() throws WebauthException {

		validator.setTimeout(0);
		validator.setMaxSkew(0);
		long issue = response_v2_firsthand_date;

		validator.validate(request, response_v2_firsthand, issue);

		try {
			validator.validate(request, response_v2_firsthand, issue - 1);
			fail("Didn't detect response issued in the future");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response apparently issued in the future; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:13:09.999 GMT", e.toString());
		}

		try {
			validator.validate(request, response_v2_firsthand, issue + 1);
			fail("Didn't detect a response that was stale");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response issued too long ago; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:13:10.001 GMT", e.toString());
		}

	}

	// Timeout handling, defined timeout

	public void testTimeout() throws WebauthException {

		final int TIMEOUT = TEST_TIMEOUT;

		validator.setTimeout(TIMEOUT);
		validator.setMaxSkew(0);
		long issue = response_v2_firsthand_date;

		validator.validate(request, response_v2_firsthand, issue);
		validator.validate(request, response_v2_firsthand, issue + TIMEOUT);

		try {
			validator.validate(request, response_v2_firsthand, issue - 1);
			fail("Didn't detect response issued in the future");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response apparently issued in the future; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:13:09.999 GMT", e.toString());
		}

		try {
			validator.validate(request, response_v2_firsthand, issue + TIMEOUT
					+ 1);
			fail("Didn't detect a response that was stale");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response issued too long ago; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:13:40.001 GMT", e.toString());
		}

	}

	// Timeout handling - defined skew

	public void testSkew() throws WebauthException {

		final int SKEW = 120000;

		validator.setTimeout(0);
		validator.setMaxSkew(SKEW);
		long issue = response_v2_firsthand_date;

		validator.validate(request, response_v2_firsthand, issue - SKEW);
		validator.validate(request, response_v2_firsthand, issue + SKEW);

		try {
			validator
					.validate(request, response_v2_firsthand, issue - SKEW - 1);
			fail("Didn't detect response issued in the future");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response apparently issued in the future; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:11:09.999 GMT", e.toString());
		}

		try {
			validator
					.validate(request, response_v2_firsthand, issue + SKEW + 1);
			fail("Didn't detect a response that was stale");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response issued too long ago; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:15:10.001 GMT", e.toString());
		}

	}

	// Timeout handling - defined timeout AND skew

	public void testTimeoutAndSkew() throws WebauthException {

		final int TIMEOUT = TEST_TIMEOUT;
		final int SKEW = 120000;

		validator.setTimeout(TIMEOUT);
		validator.setMaxSkew(SKEW);
		long issue = response_v2_firsthand_date;

		validator.validate(request, response_v2_firsthand, issue - SKEW);
		validator.validate(request, response_v2_firsthand, issue + TIMEOUT
				+ SKEW);

		try {
			validator
					.validate(request, response_v2_firsthand, issue - SKEW - 1);
			fail("Didn't detect response issued in the future");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response apparently issued in the future; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:11:09.999 GMT", e.toString());
		}

		try {
			validator.validate(request, response_v2_firsthand, issue + TIMEOUT
					+ SKEW + 1);
			fail("Didn't detect a response that was stale");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response issued too long ago; "
					+ "issue time 2005-03-17 15:13:10.000 GMT "
					+ "compared with 2005-03-17 15:15:40.001 GMT", e.toString());
		}

	}

	// Timeout handling - summer time date

	public void testSummerTime() throws WebauthException {

		validator.setTimeout(0);
		validator.setMaxSkew(0);
		long issue = response_summer_date;

		validator.validate(request, response_summer, issue);

		try {
			validator.validate(request, response_summer, issue - 1);
			fail("Didn't detect response issued in the future");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response apparently issued in the future; "
					+ "issue time 2005-03-31 15:56:28.000 BST "
					+ "compared with 2005-03-31 15:56:27.999 BST", e.toString());
		}

		try {
			validator.validate(request, response_summer, issue + 1);
			fail("Didn't detect a response that was stale");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "Response issued too long ago; "
					+ "issue time 2005-03-31 15:56:28.000 BST "
					+ "compared with 2005-03-31 15:56:28.001 BST", e.toString());
		}

	}

	// Test iact handling

  @SuppressWarnings("null")// can't be null as for loop only matches switch statement
  public void testIact() throws WebauthException {

    for (int v = 2; v <= 3; v++) {
      WebauthRequest req;
      WebauthResponse resp = null;

      req = new WebauthRequest();
      req.set("url", "http://raven.cam.ac.uk/debug.html");
      req.set("iact", "yes");

      switch (v) {
        case 2:
          resp = new WebauthResponse(RESPONSE_V2_SSO);
          break;
        case 3:
          resp = new WebauthResponse(RESPONSE_V3_SSO);
          break;
      }

      assertNotNull(resp);

      try {
        validator.validate(req, resp, resp.getDate("issue"));
        fail("Didn't detect unacceptable iact requirements for version " + v);
      } catch (WebauthException e) {
        assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
            + "First-hand authentication required but not " + "supplied", e.toString());
      }

    }
  }

	// Test aauth handling

	public void testAAuth() throws WebauthException {

		request.set("aauth", "pwd,foo");

		validator.validate(request, response_v2_firsthand,
				response_v2_firsthand_date);

		validator.validate(request, response_v2_sso, response_v2_sso_date);

		request.set("aauth", "foo,bar");

		try {
			validator.validate(request, response_v2_firsthand,
					response_v2_firsthand_date);
			fail("Didn't detect unacceptable auth in v2_firsthand");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "No acceptable authentication types used", e.toString());
		}

		try {
			validator.validate(request, response_v2_sso, response_v2_sso_date);
			fail("Didn't detect unacceptable auth in v2_sso");
		} catch (WebauthException e) {
			assertEquals("uk.ac.cam.ucs.webauth.WebauthException: "
					+ "No acceptable authentication types used", e.toString());
		}
	}

}
