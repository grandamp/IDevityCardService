package com.idevity.card.service.applets;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.Tag;
import org.keysupport.nist80073.cardedge.DynamicAuthTempl;
import org.keysupport.nist80073.cardedge.PIVAPDUInterface;
import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.PIVCardApplicationProperty;
import org.keysupport.smartcardio.CommandAPDU;
import org.keysupport.smartcardio.ResponseAPDU;
import org.keysupport.util.DataUtil;

import android.util.Log;

import com.idevity.card.data.CardData80073;

public abstract class Applet80073 {

	private static final String TAG = Applet80073.class.getSimpleName();
	private static final boolean debug = true;

	private CardData80073 cardData = null;
	private PIVDataObject cOBJ = null;
	private PIVDataObject pdOBJ = null;
	private PIVDataObject chuidOBJ = null;
	private PIVDataObject cacOBJ = null;
	private PrivateKey cacPri = null;
	/*
	 * The following ByteArrayOutputStream is to support
	 * command chaining.
	 */
	ByteArrayOutputStream baos = new ByteArrayOutputStream();

	/* Application Properties [BEGIN] */
	private final byte[] AID = { (byte) 0xa0, (byte) 0x00, (byte) 0x00,
			(byte) 0x03, (byte) 0x08, (byte) 0x00, (byte) 0x00, (byte) 0x10,
			(byte) 0x00, (byte) 0x01, (byte) 0x00 };
	private final byte[] TAG_ALLOC = { (byte) 0x4f, (byte) 0x05, (byte) 0xa0,
			(byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08 };
	private final String DESC = "IDEVITY_PIV_ENDPOINT_v0.01";
	private final String REF = "http://csrc.nist.gov/npivp";

	/*
	 * The ATS Historical Byte Header includes the Application Identifier for a
	 * PIV card.
	 * 
	 * ISO 14443-4 specifies that the historical bytes are optional, and are
	 * defined in ISO 7816-4.
	 * 
	 * ISO 7816-4 states that the historical bytes can be at most 15 bytes.
	 * 
	 * When using an android app such as NFC Tag info against a real PIV
	 * credential, we typically see the following bytes sent as the historical
	 * bytes:
	 * 
	 * 80F9A00000030800001000
	 * 
	 * Where:
	 * 
	 * 80 (Status information if present is contained in an optional COMPACT-TLV
	 * data object) F9 (The fist 4 bits are flagged, the last part of the byte
	 * is the size of the data) A00000030800001000 (The partial AID without
	 * version information, defined in NIST 800-73-3)
	 * 
	 * Based on this information, and the fact that CyanogenMod appears to hand
	 * off all ISO-7816 APDUs off to card emulation, we will return the
	 * following Historical Bytes to the terminal in order to fully attempt to
	 * emulate a PIV card.
	 * 
	 * In the event we clone the contents of a card that provides different
	 * historical bytes, we will use that value in lieu of our default.
	 */
	/*
	 * private static byte[] ATS_HISTORICAL_BYTES = { (byte) 0x80, (byte) 0xF9,
	 * (byte) 0xa0, (byte) 0x00, (byte) 0x00, (byte) 0x03, (byte) 0x08, (byte)
	 * 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x00 };
	 */
	/* Application Properties [END] */

	public ResponseAPDU processCommand(byte[] commandBytes) {

		ResponseAPDU response = null;

		try {
			CommandAPDU command = new CommandAPDU(commandBytes);
			
			int INS = command.getINS();
			int CLA = command.getCLA();
			int P1 = command.getP1();
			int P2 = command.getP2();
			int LEN = command.getNe();
			byte[] DATA = command.getData();

			switch (INS) {
			case 0xA4: { // `A4` - SELECT
				if (Arrays.equals(DATA, Arrays.copyOf(AID, DATA.length))) {
					/*
					 * // Include proper application property in the response //
					 * TODO: Investigate how some cards return SW1 61 SW2 //
					 * [AP.length] For now, return AP with SW_NO_ERROR appended
					 * 
					 * Seems to be the older Oberthur 5.2 cards. 
					 */
					
					if (debug) {
						Log.d(TAG, "explicit SELECT success");
					}
					resetCard();
					PIVCardApplicationProperty pcap = new PIVCardApplicationProperty( AID, TAG_ALLOC, DataUtil.getByteArray(DESC), DataUtil.getByteArray(REF));
					byte[] pcapenc;
					pcapenc = BERTLVFactory.encodeTLV(new Tag(Tag.PIV_APP_PROP_TMPL), pcap.getEncoded()).getBytes();
					response = new ResponseAPDU(pcapenc);
					response.setSW(ResponseAPDU.SW_NO_ERROR);
					break;
				} else {
					response = new ResponseAPDU(ResponseAPDU.SW_FILE_NOT_FOUND);
					break;
				}
			}
			case 0xC0: { // `C0` - GET RESPONSE
				response = getData(cOBJ, LEN);
				break;
			}
			case 0xCB: { // `CB` - GET DATA
				resetData();
				if (command.equals(getDataAPDU(new Tag(Tag.PIV_DISCOVERY_OBJECT))) && pdOBJ != null) {
					cOBJ = pdOBJ;
					response = getData(cOBJ, LEN);
				} else if (command.equals(getDataAPDU(new Tag(Tag.PIV_CHUID))) && chuidOBJ != null) {
					cOBJ = chuidOBJ;
					response = getData(cOBJ, LEN);
				} else if (command.equals(getDataAPDU(new Tag(Tag.PIV_CERT_CARDAUTH))) && cacOBJ != null) {
					cOBJ = cacOBJ;
					response = getData(cOBJ, LEN);
				} else {
					if (debug) {
						Log.d(TAG, "GET DATA file not found");
					}
					response = new ResponseAPDU(ResponseAPDU.SW_FILE_NOT_FOUND);
				}
				break;
			}
			case 0x87: { // `87` - GENERAL AUTHENTICATE
				switch (CLA) {
				case 0: { // `00` - No Command Chaining
					baos.write(DATA);
					byte[] _data = baos.toByteArray();
					if (debug) {
						Log.d(TAG, "P1: " + DataUtil.byteToString((byte)P1) + " P2: " + DataUtil.byteToString((byte)P2) + " DATA: " + DataUtil.byteArrayToString(_data));
						Log.d(TAG, "GENERAL AUTHENTICATE");
					}
					if (cacPri != null) {
						cOBJ = new PIVDataObject(genAuthSign(_data));
						response = getData(cOBJ, LEN);
					} else {
						response = new ResponseAPDU(ResponseAPDU.SW_FUNC_NOT_SUPPORTED);
					}
					break;
				}
				case 16: { // `10` - Command Chaining
					baos.write(DATA);
					response = new ResponseAPDU(ResponseAPDU.SW_NO_ERROR);
					break;
				}
				default: {
					break;
				}
				}
				break;
			}
			default: {
				// Should not get here
				if (debug) {
					Log.d(TAG, "Unknown Command");
				}
				response = new ResponseAPDU(ResponseAPDU.SW_UNKNOWN);
				break;
			}
			}
		} catch (IOException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}
		/*
		 * Return the first response from the iterator, rely on the terminal app to come back for more.
		 */
		return response;
	}

	private ResponseAPDU getData(PIVDataObject dataObject, int len) {
		ResponseAPDU response = null;
		if (len > dataObject.available()) {
			len = dataObject.available();
		}
		if (len <= 0 || len > 256) {
			len = 256;
		}
		response = new ResponseAPDU(dataObject.read(len));
		if (dataObject.available() > 256) {
			response.setSW(new byte[] { (byte) 0x61, (byte) 0x00 });
		} else if (dataObject.available() > 0){
			response.setSW(new byte[] { (byte) 0x61, (byte) dataObject.available() });
		} else {
			response.setSW(ResponseAPDU.SW_NO_ERROR);
		}
		return response;
	}
	
	private static CommandAPDU getDataAPDU(Tag pivObjectTag) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] tag_bytes = pivObjectTag.getBytes();
		baos.write(PIVAPDUInterface.PIV_GET_DATA_HEADER);
		baos.write(tag_bytes.length + 2);
		baos.write((byte) 0x5c);
		baos.write(tag_bytes.length);
		baos.write(tag_bytes);
		baos.write(0x00);
		return new CommandAPDU(baos.toByteArray());
	}

	protected void setCardData(CardData80073 data) {
		cardData = data;
		/*
		 * Initialize Discovery Object
		 */
		PIVDataTempl pdo = cardData.getPIVDiscoveryObject();
		if (pdo != null) {
			pdOBJ = new PIVDataObject(pdo.getEncoded());
		}
		/*
		 * Initialize CHUID Object
		 */
		PIVDataTempl chuid = cardData.getPIVCardHolderUniqueID();
		if (chuid != null) {
			chuidOBJ = new PIVDataObject(chuid.getEncoded());
		}
		/*
		 * Initialize Card Authentication Certificate (if present)
		 * 
		 * -and-
		 * 
		 * Associated private key (if present)
		 */
		PIVDataTempl cac = cardData.getCardAuthCertificate();
		if (cac != null) {
			cacOBJ = new PIVDataObject(cac.getEncoded());
			cacPri = (PrivateKey) cardData.getCardAuthPrivate();
		}
		if (debug) {
			Log.d(TAG, "Card Data initialized");
		}
	}
	
	private void resetData() {
		cOBJ = null;
		if (pdOBJ != null) {
			pdOBJ.reset();
		}
		if (chuidOBJ != null) {
			chuidOBJ.reset();
		}
		if (cacOBJ != null) {
			cacOBJ.reset();
		}
	}

	private void resetCard() {
		resetData();
		baos.reset();
	}
	
	public CardData80073 getCardData() {
		return cardData;
	}
	
	private byte[] genAuthSign(byte[] plaintext) {
		
		DynamicAuthTempl gaReq = new DynamicAuthTempl(
				plaintext);
		byte[] ciphertext = encrypt(gaReq.getTemplateValue());
		DynamicAuthTempl gaRes = new DynamicAuthTempl(
				DynamicAuthTempl.POP_TO_CARD_SYM, ciphertext);
		return gaRes.getEncoded();
	}
	
	private byte[] encrypt(byte[] plaintext) {
		byte[] ciphertext = null;
		Cipher cipher;
		try {
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, cacPri);
			ciphertext = cipher.doFinal(plaintext);
		} catch (NoSuchAlgorithmException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		} catch (NoSuchPaddingException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		} catch (InvalidKeyException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		} catch (IllegalBlockSizeException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		} catch (BadPaddingException e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}
		return ciphertext;
	}
	

}
