/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * @author John Calla (john@idevity.com)
 *
 *****************************************************************************/

package com.idevity.android.nfc;

import java.util.Arrays;
import java.util.Enumeration;

import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.util.DataUtil;

/**
 * This class will become more full featured over time, as the
 * intent is to use with our own CCID solution.
 * 
 * It will process the historical bytes and tell us more information
 * about the card.
 * 
 * For now, we just need to identify if the PIV card application is
 * implicitly selected.
 * 
 * While 800-73-3 requires implicit selection, I am unaware of the
 * original requirements.  Gemalto does not indicate implicit
 * selection in it's ATRs for it's newer cards, but the cards are
 * compliant with 800-73-3.  We should not approach this from a
 * NIST compliance perspective, but from an ISO 7816-4 perspective.
 * 
 * This may mean that all Gemalto cards will receive an explicit
 * select command.
 * 
 * Beyond implicit selection, we are also interested to know if
 * explicit selection is permissible for partial or full selects.
 * 
 * @author tejohnson
 *
 */
public class HistoricalBytes {
	
	private final static boolean debug = false;

	private final static byte CI_NONTLV = (byte)0x00;
	private final static byte CI_DIR = (byte)0x10;
	private final static byte CI_TLV = (byte)0x80;
	private final static byte CI_RFU_01 = (byte)0x81;
	private final static byte CI_RFU_02 = (byte)0x82;
	private final static byte CI_RFU_03 = (byte)0x83;
	private final static byte CI_RFU_04 = (byte)0x84;
	private final static byte CI_RFU_05 = (byte)0x85;
	private final static byte CI_RFU_06 = (byte)0x86;
	private final static byte CI_RFU_07 = (byte)0x87;
	private final static byte CI_RFU_08 = (byte)0x88;
	private final static byte CI_RFU_09 = (byte)0x89;
	private final static byte CI_RFU_10 = (byte)0x8A;
	private final static byte CI_RFU_11 = (byte)0x8B;
	private final static byte CI_RFU_12 = (byte)0x8C;
	private final static byte CI_RFU_13 = (byte)0x8D;
	private final static byte CI_RFU_14 = (byte)0x8E;
	private final static byte CI_RFU_15 = (byte)0x8F;
	
	private byte[] selectedApp = null;
	private boolean implicitSelected = false;
	private boolean selectPartial = false;
	private boolean selectFull = false;

	/**
	 * 
	 */
	@SuppressWarnings("unused")
	private HistoricalBytes() {
		//Hide default constructor
	}

	/**
	 * 
	 */
	public HistoricalBytes(byte[] hbBytes) {
		/*
		 * Parse the bytes, and initialize our global vars
		 */
		if (hbBytes.length > 0) {
			switch(hbBytes[0]) {
			case CI_NONTLV: {
				if (debug) {
					System.out.println("Category Byte(00): Status information at the end of the historical bytes");
				}
				break;
			}
			case CI_DIR: {
				if (debug) {
					System.out.println("Category Byte(10): The following byte is the DIR data reference");
				}
				break;
			}
			case CI_TLV: {
				if (debug) {
					System.out.println("Category Byte(80): Status information is contained in an optional COMPACT-TLV data object");
				}
				processCTLV(Arrays.copyOfRange(hbBytes, 1, hbBytes.length));
				break;
			}
			case CI_RFU_01: {
				if (debug) {
					System.out.println("Category Byte(81): Reserved for future use");
				}
				break;
			}
			case CI_RFU_02: {
				if (debug) {
					System.out.println("Category Byte(82): Reserved for future use");
				}
				break;
			}
			case CI_RFU_03: {
				if (debug) {
					System.out.println("Category Byte(83): Reserved for future use");
				}
				break;
			}
			case CI_RFU_04: {
				if (debug) {
					System.out.println("Category Byte(84): Reserved for future use");
				}
				break;
			}
			case CI_RFU_05: {
				if (debug) {
					System.out.println("Category Byte(85): Reserved for future use");
				}
				break;
			}
			case CI_RFU_06: {
				if (debug) {
					System.out.println("Category Byte(86): Reserved for future use");
				}
				break;
			}
			case CI_RFU_07: {
				if (debug) {
					System.out.println("Category Byte(87): Reserved for future use");
				}
				break;
			}
			case CI_RFU_08: {
				if (debug) {
					System.out.println("Category Byte(88): Reserved for future use");
				}
				break;
			}
			case CI_RFU_09: {
				if (debug) {
					System.out.println("Category Byte(89): Reserved for future use");
				}
				break;
			}
			case CI_RFU_10: {
				if (debug) {
					System.out.println("Category Byte(8A): Reserved for future use");
				}
				break;
			}
			case CI_RFU_11: {
				if (debug) {
					System.out.println("Category Byte(8B): Reserved for future use");
				}
				break;
			}
			case CI_RFU_12: {
				if (debug) {
					System.out.println("Category Byte(8C): Reserved for future use");
				}
				break;
			}
			case CI_RFU_13: {
				if (debug) {
					System.out.println("Category Byte(8D): Reserved for future use");
				}
				break;
			}
			case CI_RFU_14: {
				if (debug) {
					System.out.println("Category Byte(8E): Reserved for future use");
				}
				break;
			}
			case CI_RFU_15: {
				if (debug) {
					System.out.println("Category Byte(8F): Reserved for future use");
				}
				break;
			}
			default: {
				if (debug) {
					System.out.println("Category Byte(" + DataUtil.byteToString(hbBytes[0]) + "): Proprietary");
				}
				break;
			}
			}
		}
	}

	private void processCTLV(byte[] CTLV) {
		Enumeration<TLV> tlvs = CompactTLVFactory.decodeTLV(CTLV);
		while (tlvs.hasMoreElements()) {

			TLV child_tlv = (TLV) tlvs.nextElement();
			Tag child_tag = child_tlv.getTag();
			byte[] value = child_tlv.getValue();

			switch (child_tag.getBytes()[0]) {
			case (byte)0x30: {
				selectFull = (value[0] & (byte)0x80) == (byte)0x80; 
				selectPartial = (value[0] & (byte)0x80) == (byte)0x40;
				implicitSelected  = (value[0] & (byte)0x80) == (byte)0x40;
				break;
			}
			case (byte)0xF0: {
				selectedApp = value;
				implicitSelected = true;
				if (debug) {
					System.out.println("Application is implicitly selected.  AID: " + DataUtil.byteArrayToString(selectedApp));
				}
				break;
			}
			default: {
				break;
			}
			}
		}

	}
	/**
	 * @return the selectedApp
	 */
	public byte[] getSelectedAppAID() {
		return selectedApp;
	}

	/**
	 * @return the implicitSelected
	 */
	public boolean isAppImplicitSelected() {
		return implicitSelected;
	}

	/**
	 * @return the selectPartial
	 */
	public boolean allowsPartialSelect() {
		return selectPartial;
	}

	/**
	 * @return the selectFull
	 */
	public boolean allowsFullSelect() {
		return selectFull;
	}

}
