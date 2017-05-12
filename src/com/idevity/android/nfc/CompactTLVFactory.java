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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.util.Enumeration;
import java.util.Vector;

import org.keysupport.encoding.TLV;
import org.keysupport.util.DataUtil;

/**
 * The logic for Compact TLV is much more simple
 * than BER or DER encodings.
 * 
 * For a TLV object, the Tag and Length are encoded
 * in a single byte.  I.e.,
 * 
 * F9A00000030800001000 = 
 *     TAG:15 LEN:9 VAL:A00000030800001000
 * 
 * @author tejohnson
 * 
 */
public class CompactTLVFactory {

	private final static boolean debug = false;
	private final static byte TMASK = (byte)0xF0;
	private final static byte LMASK = (byte)0x0F;

	/**
	 *
	 */
	private CompactTLVFactory() {
		// Hide default constructor
	}

	/**
	 * @param TLV
	
	 * @return Enumeration<TLV> An enumeration of BER TLV objects. */
	public static Enumeration<TLV> decodeTLV(byte[] TLV) {

		if (debug) {
			System.out.println("TLV BYTES LENGTH: " + TLV.length);
		}
		int index = 0;
		Vector<TLV> tlvs = new Vector<TLV>();

		while (index < TLV.length) {
			byte[] tag = null;
			int length = 0;
			byte[] value = null;
			byte[] full_tlv = null;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();

			int start_index = index;

			// Parse the tag
			baos.write((byte) (TLV[index] & TMASK));
			tag = baos.toByteArray();
			baos.reset();
			// Parse the length
			baos.write((byte) (TLV[index] & LMASK));
			byte[] encoded_length = baos.toByteArray();
			baos.reset();
			index++;

			if (index < TLV.length) {
				length = new BigInteger(1, encoded_length).intValue();
				if (debug) {
					System.out.println("LEN:" + length);
				}
				int header_len = index - start_index;

				// Parse the value based off of the length
				value = new byte[length];
				System.arraycopy(TLV, index, value, 0, length);
				if (debug) {
					System.out.println("VAL:"
							+ DataUtil.byteArrayToString(value));
				}
				index = index + length;
				int full_tlv_len = header_len + length;
				if (debug) {
					System.out.println("Decoded TLV is " + full_tlv_len
							+ " bytes long.");
				}
				full_tlv = new byte[full_tlv_len];
				System.arraycopy(TLV, start_index, full_tlv, 0, full_tlv_len);
				// Create TLV object
				TLV current_tlv = new TLV(tag, encoded_length, value, full_tlv);
				// add new TLV to the Vector
				if (debug) {
					System.out.println("-----Begin Decoded TLV-----");
					System.out.println(current_tlv.toString());
					System.out.println("------End Decoded TLV------");
				}
				tlvs.add(current_tlv);
			} else {
				// Do nothing
			}
		}
		Enumeration<TLV> tlve = tlvs.elements();
		return tlve;
	}

	/**
	 * @param tag
	 * @param value
	
	 * @return TLV A fully encoded TLV object. */
//  TODO:  Write an encoding method
//	public static TLV encodeTLV(Tag tag, byte[] value) {
//	}

}