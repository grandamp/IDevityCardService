package com.idevity.card.read;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: Globals.java 307 2014-02-03 00:56:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $ 
 * 
 * Changed: $LastChangedDate: 2014-02-02 19:56:22 -0500 (Sun, 02 Feb 2014) $
 *****************************************************************************/
public class Globals {

	private static Globals instance;

	// Global variable
	public final static String AGENCY_CODE = "AGENCYCODE";
	public final static String SYSTEM_CODE = "SYSTEMCODE";
	public final static String CRED_NUMBER = "CREDNUMBER";
	public final static String PI = "PERSONID";
	public final static String ORG_CATEGORY = "ORGCATEGORY";
	public final static String ORG_ID = "ORGID";
	public final static String POA = "POA";
	public final static String EXPIRY_DATE = "EXPIRYDATE";
	public final static String GUID = "GUID";
	public final static String PROFILE_NAME = "PROFILE_NAME";
	public final static String PROFILE_ID = "PROFILE_ID";
	public final static String PROFILE_FILENAME = "PROFILE_FILENAME";
	public final static String BRUTE = "BRUTE";
	public final static String CARDDATA = "CARD_DATA";
	public final static String READERLOG = "READER_LOG";
	public final static String SHOWLOG = "pref_showlog";
	public final static String SHOWDEBUG = "pref_showdebug";
	public final static String ENABLEPOP = "pref_enablepop";
	public final static String DEFAULTEMAIL = "pref_defaultemail";
	public static int TABNO = 4;

	public static byte[] currentcarddata;
	public static String currentlogdata;

	// Restrict the constructor from being instantiated
	private Globals() {
	}

	/**
	 * Method getShowLog
	 * 
	 * @return String
	 */
	public String getShowLog() {
		return Globals.SHOWLOG;
	}

	/**
	 * Method getShowDebug
	 * 
	 * @return String
	 */
	public String getShowDebug() {
		return Globals.SHOWDEBUG;
	}

	/**
	 * Method getEnablePOP
	 * 
	 * @return String
	 */
	public String getEnablePOP() {
		return Globals.ENABLEPOP;
	}

	/**
	 * Method getDefaultEmail
	 * 
	 * @return String
	 */
	public String getDefaultEmail() {
		return Globals.DEFAULTEMAIL;
	}

	/**
	 * Method getAgencyCodeString.
	 * 
	 * @return String
	 */
	public String getAgencyCodeString() {
		return Globals.AGENCY_CODE;
	}

	/**
	 * Method getSystemCodeString.
	 * 
	 * @return String
	 */
	public String getSystemCodeString() {
		return Globals.SYSTEM_CODE;
	}

	/**
	 * Method getCredNumberString.
	 * 
	 * @return String
	 */
	public String getCredNumberString() {
		return Globals.CRED_NUMBER;
	}

	/**
	 * Method getPersonIdString.
	 * 
	 * @return String
	 */
	public String getPersonIdString() {
		return Globals.PI;
	}

	/**
	 * Method getOrgCatString.
	 * 
	 * @return String
	 */
	public String getOrgCatString() {
		return Globals.ORG_CATEGORY;
	}

	/**
	 * Method getOrgIdString.
	 * 
	 * @return String
	 */
	public String getOrgIdString() {
		return Globals.ORG_ID;
	}

	/**
	 * Method getPOAString.
	 * 
	 * @return String
	 */
	public String getPOAString() {
		return Globals.POA;
	}

	/**
	 * Method getExpiryDateString.
	 * 
	 * @return String
	 */
	public String getExpiryDateString() {
		return Globals.EXPIRY_DATE;
	}

	/**
	 * Method getProfileNameString.
	 * 
	 * @return String
	 */
	public String getProfileNameString() {
		return Globals.PROFILE_NAME;
	}

	/**
	 * Method getProfileIdString.
	 * 
	 * @return String
	 */
	public String getProfileIdString() {
		return Globals.PROFILE_ID;
	}

	/**
	 * Method getGUIDString.
	 * 
	 * @return String
	 */
	public String getGUIDString() {
		return Globals.GUID;
	}

	/**
	 * Method getProfileFileNameString.
	 * 
	 * @return String
	 */
	public String getProfileFileNameString() {
		return Globals.PROFILE_FILENAME;
	}

	/**
	 * Method getBruteString.
	 * 
	 * @return String
	 */
	public String getBruteString() {
		return Globals.BRUTE;
	}

	/**
	 * Method getBruteString.
	 * 
	 * @return String
	 */
	public String getCardData() {
		return Globals.CARDDATA;
	}

	/**
	 * Method getBruteString.
	 * 
	 * @return String
	 */
	public String getReaderLog() {
		return Globals.READERLOG;
	}

	public void putCard(byte[] _data) {
		Globals.currentcarddata = _data;
	}

	public void putLogData(String _log) {
		Globals.currentlogdata = _log;
	}

	public String getLogData() {
		return Globals.currentlogdata;
	}

	public byte[] getCard() {
		return Globals.currentcarddata;
	}

	public void putTabNo(int num) {
		Globals.TABNO = num;
	}

	public int getTabNo() {
		return Globals.TABNO;
	}

	/**
	 * Method getInstance.
	 * 
	 * @return Globals
	 */
	public static synchronized Globals getInstance() {
		if (instance == null) {
			instance = new Globals();
		}
		return instance;
	}

}