/**
 * 
 */
package com.idevity.card.data;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Enumeration;

import javax.crypto.spec.SecretKeySpec;

import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.Tag;
import org.keysupport.keystore.DigestEngine;
import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.util.DataUtil;

/**
 * This class will provide the representation of an 800-73 based credential for the purposes of emulating.
 * 
 * Specifically, it will provide the all data elements defined in the 800-73 Data Model and Card Edge interface
 *
 * In addition, the following elements will be held for a specific Card:
 * 		-ATS Historical Bytes (Need or use is debatable)
 *		-Card Production Lifecycle Data (Need or use is debatable)
 *		-Contactless Credential Serial Number (32/56/80 bit formats) (Used by some HID Reader Configurations)
 *
 * All objects will be serialized in a BER-TLV encoding for storage to a file in binary format, by way to a toByteArray() method. (use ByteArrayInputStream with the File I/O to read in the data)
 * 
 * I.e., to save a profile...
 * 
 * The binary format (byte[]) will be used to initialize this object (use ByteArrayInputStream with the File I/O to read in the data)
 * 
 * I.e., to load a profile...
 * 
 * The constructor will allow the creation of a zero filled object that can be fully initialized using setter methods.
 * 
 * I.e., to create a profile from scratch, or create a profile during cloning. Ex: CardData80073.setCHUID(PIVCardHolderUniqueID chuid)
 * 
 * There will be numerous getter methods so the card emulator can obtain the data as needed in order to effectively emulate a card.
 * 
 * Once this DataObject is created/populated, call the digestString() method on the object to get a String SHA-1 digest of the Card Data.
 * This String can be used for the filename.  Ex:  String filename = carddata.digestString() + ".ber";  Then, the data from this object can 
 * be pulled to store in the file.  I.e., byte[] data = carddata.toByteArray(); Below is a code sample of saving a CardData object to a file:
 * 
 * In this example, the CardData80073 object is simply "carddata":
 * 
 * CardData80073 carddata = new CardData80073();
 * 
 * ...Code to populate a CHUID object with a FASCN, etc...
 * ...Code to populate the carddata object with the CHUID...
 * 
 * String filename = carddata.digestString() + ".ber";
 * FileOutputStream fos = openFileOutput(filename, Context.MODE_PRIVATE);
 * fos.write(carddata.toByteArray());
 * fos.close();
 * 
 * Binary Data Format / TLV Encoding of objects via Tags 0x9F01 - 0x9F7F: 
 * _________________________________________________________________________________________________
 * | Tag      | Value                                                                               |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F01   | ATS Historical Bytes (Need or use is debatable)                                     |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F02   | CPLC - Card Production Lifecycle Data (Need or use is debatable)                    |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F03   | CSN/UID/CID - Card Identifier Defined in ISO/IEC 14443-3 for anti-collision         |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F04   | PIV Card Application Property Defined in NIST 800-73-4 Part 2                       |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F05   | PIV Admin Key Type                                                                  |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F06   | PIV Admin Key Type Defined in NIST 800-73-4 Part 2                                  |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F07   | Card Capability Container Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F08   | Card Holder Unique Identifier Defined in NIST 800-73-4 Part 2                       |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F09   | PIV Authentication Certificate Defined in NIST 800-73-3 Part 2                      |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F0A   | PIV Authentication Certificate Private Key                                          |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F0B   | Card Holder Fingerprints Defined in NIST 800-73-4 Part 2                            |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F0C   | Security Object Defined in NIST 800-73-4 Part 2                                     |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F0D   | Card Holder Facial Image Defined in NIST 800-73-4 Part 2                            |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F0E   | Card Authentication Certificate Defined in NIST 800-73-4 Part 2                     |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F0F   | Card Authentication Certificate Private Key                                         |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F10   | Card Authentication Symmetric Key Type                                              |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F11   | Card Authentication Symmetric Key Defined in NIST 800-73-4 Part 2                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F12   | Digital Signature Certificate Defined in NIST 800-73-4 Part 2                       |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F13   | Digital Signature Certificate Private Key                                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F14   | Key Management Certificate Defined in NIST 800-73-4 Part 2                          |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F15   | Key Management Certificate Private Key                                              |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F16   | Printed Information  Defined in NIST 800-73-4 Part 2                                |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F17   | PIV Discovery Object Defined in NIST 800-73-4 Part 2                                |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F18   | Key History Object Defined in NIST 800-73-4 Part 2                                  |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F19   | RFU                                                                                 |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F1A   | Retired KM Certificate 01 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F1B   | Retired KM Key 01                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F1C   | Retired KM Certificate 02 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F1D   | Retired KM Key 02                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F1E   | Retired KM Certificate 03 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F1F   | Retired KM Key 03                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F20   | Retired KM Certificate 04 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F21   | Retired KM Key 04                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F22   | Retired KM Certificate 05 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F23   | Retired KM Key 05                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F24   | Retired KM Certificate 06 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F25   | Retired KM Key 06                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F26   | Retired KM Certificate 07 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F27   | Retired KM Key 07                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F28   | Retired KM Certificate 08 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F29   | Retired KM Key 08                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F2A   | Retired KM Certificate 09 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F2B   | Retired KM Key 09                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F2C   | Retired KM Certificate 10 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F2D   | Retired KM Key 10                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F2E   | Retired KM Certificate 11 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F2F   | Retired KM Key 11                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F30   | Retired KM Certificate 12 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F31   | Retired KM Key 12                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F32   | Retired KM Certificate 13 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F33   | Retired KM Key 13                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F34   | Retired KM Certificate 14 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F35   | Retired KM Key 14                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F36   | Retired KM Certificate 15 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F37   | Retired KM Key 15                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F38   | Retired KM Certificate 16 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F39   | Retired KM Key 16                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F3A   | Retired KM Certificate 17 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F3B   | Retired KM Key 17                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F3C   | Retired KM Certificate 18 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F3D   | Retired KM Key 18                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F3E   | Retired KM Certificate 19 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F3F   | Retired KM Key 19                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F40   | Retired KM Certificate 20 Defined in NIST 800-73-4 Part 2                           |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F41   | Retired KM Key 20                                                                   |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F42   | Cardholder Iris Images Defined in NIST 800-73-4 Part 2                              |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F43   | Biometric Information Templates Group Template Defined in NIST 800-73-4 Part 2      |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F44   | Secure Messaging Certificate Signer Defined in NIST 800-73-4 Part 2                 |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F45   | Secure Messaging Key                                                                |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F46   | Pairing Code Reference Data Defined in NIST 800-73-4 Part 2                         |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F47   | CAK Proof of Posession Nonce                                                        |
 * |----------|-------------------------------------------------------------------------------------|
 * | 0x9F48   | CAK Proof of Posession Signature                                                    |
 * |----------|-------------------------------------------------------------------------------------|
 * | 49 - 7F  | RFU                                                                                 |
 * |----------|-------------------------------------------------------------------------------------|
 * 
 * TODO: Add Global PIN
 * TODO: Add PIV Application PIN
 * TODO: Add PIN Unblocking Key
 * TODO: Add Pairing Code
 * TODO: Add GP ISD Keyset
 * TODO: Add GP ASD Keyset
 * 
 * @version $Revision: 2.0 $
 */
public class CardData80073 {
	/*
	 * TAG Variables Follow
	 */
	/**
	 * ATS Historical Bytes
	 */
	private static final byte[] TAG_ATSHB = new byte[] { (byte)0x9F, (byte)0x01 };
	/**
	 * Card Production Lifecycle Data
	 */
	private static final byte[] TAG_CPLC = new byte[] { (byte)0x9F, (byte)0x02 };
	/**
	 * CSN/UID
	 */
	private static final byte[] TAG_CSN = new byte[] { (byte)0x9F, (byte)0x03 };
	/**
	 * Application Property
	 */
	private static final byte[] TAG_PCAP = new byte[] { (byte)0x9F, (byte)0x04 };
	/**
	 * Key Type
	 */
	private static final byte[] TAG_PADMIN_KEY_TYPE = new byte[] { (byte)0x9F, (byte)0x05 };
	/**
	 * PIV Admin Key
	 */
	private static final byte[] TAG_PADMIN_KEY = new byte[] { (byte)0x9F, (byte)0x06 };
	/**
	 * Card Capability Container
	 */
	private static final byte[] TAG_CCC = new byte[] { (byte)0x9F, (byte)0x07 };
	/**
	 * CardHolderUniqueIdentifier
	 */
	private static final byte[] TAG_CHUID = new byte[] { (byte)0x9F, (byte)0x08 };
	/**
	 * PIV Authentication Certificate
	 */
	private static final byte[] TAG_PAC = new byte[] { (byte)0x9F, (byte)0x09 };
	/**
	 * PIV Authentication Certificate Private Key
	 */
	private static final byte[] TAG_PAK = new byte[] { (byte)0x9F, (byte)0x0A };
	/**
	 * Cardholder Fingerprints
	 */
	private static final byte[] TAG_CHF = new byte[] { (byte)0x9F, (byte)0x0B };
	/**
	 * Security Object
	 */
	private static final byte[] TAG_SO = new byte[] { (byte)0x9F, (byte)0x0C };
	/**
	 * Cardholder Facial Image
	 */
	private static final byte[] TAG_CFI = new byte[] { (byte)0x9F, (byte)0x0D };
	/**
	 * Card Authentication Certificate
	 */
	private static final byte[] TAG_CAC = new byte[] { (byte)0x9F, (byte)0x0E };
	/**
	 * Card Authentication Certificate Private Key
	 */
	private static final byte[] TAG_CAK = new byte[] { (byte)0x9F, (byte)0x0F };
	/**
	 * Card Authentication Symmetric Key Type
	 */
	private static final byte[] TAG_SYM_CAK_TYPE = new byte[] { (byte)0x9F, (byte)0x10 };
	/**
	 * Card Authentication Symmetric Key
	 */
	private static final byte[] TAG_SYM_CAK = new byte[] { (byte)0x9F, (byte)0x11 };
	/**
	 * Digital Signature Certificate
	 */
	private static final byte[] TAG_DSC = new byte[] { (byte)0x9F, (byte)0x12 };
	/**
	 * Digital Signature Certificate Private Key
	 */
	private static final byte[] TAG_DSK = new byte[] { (byte)0x9F, (byte)0x13 };
	/**
	 * Key Management Certificate
	 */
	private static final byte[] TAG_KMC = new byte[] { (byte)0x9F, (byte)0x14 };
	/**
	 * Key Management Certificate Private Key
	 */
	private static final byte[] TAG_KMK = new byte[] { (byte)0x9F, (byte)0x15 };
	/**
	 * Printed Information
	 */
	private static final byte[] TAG_PI = new byte[] { (byte)0x9F, (byte)0x16 };
	/**
	 * Discovery Object
	 */
	private static final byte[] TAG_DO = new byte[] { (byte)0x9F, (byte)0x17 };
	/**
	 * Key History Object
	 */
	private static final byte[] TAG_KHO = new byte[] { (byte)0x9F, (byte)0x18 };
	/**
	 * RFU 1
	 */
	@SuppressWarnings("unused")
	private static final byte[] TAG_RFU_01 = new byte[] { (byte)0x9F, (byte)0x19 };
	/**
	 * Retired Key Management Certificate 01
	 */
	private static final byte[] TAG_KMC_01 = new byte[] { (byte)0x9F, (byte)0x1A };
	/**
	 * Retired Key Management Certificate 01 Private Key
	 */
	private static final byte[] TAG_KMK_01 = new byte[] { (byte)0x9F, (byte)0x1B };
	/**
	 * Retired Key Management Certificate 02
	 */
	private static final byte[] TAG_KMC_02 = new byte[] { (byte)0x9F, (byte)0x1C };
	/**
	 * Retired Key Management Certificate 02 Private Key
	 */
	private static final byte[] TAG_KMK_02 = new byte[] { (byte)0x9F, (byte)0x1D };
	/**
	 * Retired Key Management Certificate 03
	 */
	private static final byte[] TAG_KMC_03 = new byte[] { (byte)0x9F, (byte)0x1E };
	/**
	 * Retired Key Management Certificate 03 Private Key
	 */
	private static final byte[] TAG_KMK_03 = new byte[] { (byte)0x9F, (byte)0x1F };
	/**
	 * Retired Key Management Certificate 04
	 */
	private static final byte[] TAG_KMC_04 = new byte[] { (byte)0x9F, (byte)0x20 };
	/**
	 * Retired Key Management Certificate 04 Private Key
	 */
	private static final byte[] TAG_KMK_04 = new byte[] { (byte)0x9F, (byte)0x21 };
	/**
	 * Retired Key Management Certificate 05
	 */
	private static final byte[] TAG_KMC_05 = new byte[] { (byte)0x9F, (byte)0x22 };
	/**
	 * Retired Key Management Certificate 05 Private Key
	 */
	private static final byte[] TAG_KMK_05 = new byte[] { (byte)0x9F, (byte)0x23 };
	/**
	 * Retired Key Management Certificate 06
	 */
	private static final byte[] TAG_KMC_06 = new byte[] { (byte)0x9F, (byte)0x24 };
	/**
	 * Retired Key Management Certificate 06 Private Key
	 */
	private static final byte[] TAG_KMK_06 = new byte[] { (byte)0x9F, (byte)0x25 };
	/**
	 * Retired Key Management Certificate 07
	 */
	private static final byte[] TAG_KMC_07 = new byte[] { (byte)0x9F, (byte)0x26 };
	/**
	 * Retired Key Management Certificate 07 Private Key
	 */
	private static final byte[] TAG_KMK_07 = new byte[] { (byte)0x9F, (byte)0x27 };
	/**
	 * Retired Key Management Certificate 08
	 */
	private static final byte[] TAG_KMC_08 = new byte[] { (byte)0x9F, (byte)0x28 };
	/**
	 * Retired Key Management Certificate 08 Private Key
	 */
	private static final byte[] TAG_KMK_08 = new byte[] { (byte)0x9F, (byte)0x29 };
	/**
	 * Retired Key Management Certificate 09
	 */
	private static final byte[] TAG_KMC_09 = new byte[] { (byte)0x9F, (byte)0x2A };
	/**
	 * Retired Key Management Certificate 09 Private Key
	 */
	private static final byte[] TAG_KMK_09 = new byte[] { (byte)0x9F, (byte)0x2B };
	/**
	 * Retired Key Management Certificate 10
	 */
	private static final byte[] TAG_KMC_10 = new byte[] { (byte)0x9F, (byte)0x2C };
	/**
	 * Retired Key Management Certificate 10 Private Key
	 */
	private static final byte[] TAG_KMK_10 = new byte[] { (byte)0x9F, (byte)0x2D };
	/**
	 * Retired Key Management Certificate 11
	 */
	private static final byte[] TAG_KMC_11 = new byte[] { (byte)0x9F, (byte)0x2E };
	/**
	 * Retired Key Management Certificate 11 Private Key
	 */
	private static final byte[] TAG_KMK_11 = new byte[] { (byte)0x9F, (byte)0x2F };
	/**
	 * Retired Key Management Certificate 12
	 */
	private static final byte[] TAG_KMC_12 = new byte[] { (byte)0x9F, (byte)0x30 };
	/**
	 * Retired Key Management Certificate 12 Private Key
	 */
	private static final byte[] TAG_KMK_12 = new byte[] { (byte)0x9F, (byte)0x31 };
	/**
	 * Retired Key Management Certificate 13
	 */
	private static final byte[] TAG_KMC_13 = new byte[] { (byte)0x9F, (byte)0x32 };
	/**
	 * Retired Key Management Certificate 13 Private Key
	 */
	private static final byte[] TAG_KMK_13 = new byte[] { (byte)0x9F, (byte)0x33 };
	/**
	 * Retired Key Management Certificate 14
	 */
	private static final byte[] TAG_KMC_14 = new byte[] { (byte)0x9F, (byte)0x34 };
	/**
	 * Retired Key Management Certificate 14 Private Key
	 */
	private static final byte[] TAG_KMK_14 = new byte[] { (byte)0x9F, (byte)0x35 };
	/**
	 * Retired Key Management Certificate 15
	 */
	private static final byte[] TAG_KMC_15 = new byte[] { (byte)0x9F, (byte)0x36 };
	/**
	 * Retired Key Management Certificate 15 Private Key
	 */
	private static final byte[] TAG_KMK_15 = new byte[] { (byte)0x9F, (byte)0x37 };
	/**
	 * Retired Key Management Certificate 16
	 */
	private static final byte[] TAG_KMC_16 = new byte[] { (byte)0x9F, (byte)0x38 };
	/**
	 * Retired Key Management Certificate 16 Private Key
	 */
	private static final byte[] TAG_KMK_16 = new byte[] { (byte)0x9F, (byte)0x39 };
	/**
	 * Retired Key Management Certificate 17
	 */
	private static final byte[] TAG_KMC_17 = new byte[] { (byte)0x9F, (byte)0x3A };
	/**
	 * Retired Key Management Certificate 17 Private Key
	 */
	private static final byte[] TAG_KMK_17 = new byte[] { (byte)0x9F, (byte)0x3B };
	/**
	 * Retired Key Management Certificate 18
	 */
	private static final byte[] TAG_KMC_18 = new byte[] { (byte)0x9F, (byte)0x3C };
	/**
	 * Retired Key Management Certificate 18 Private Key
	 */
	private static final byte[] TAG_KMK_18 = new byte[] { (byte)0x9F, (byte)0x3D };
	/**
	 * Retired Key Management Certificate 19
	 */
	private static final byte[] TAG_KMC_19 = new byte[] { (byte)0x9F, (byte)0x3E };
	/**
	 * Retired Key Management Certificate 19 Private Key
	 */
	private static final byte[] TAG_KMK_19 = new byte[] { (byte)0x9F, (byte)0x3F };
	/**
	 * Retired Key Management Certificate 20
	 */
	private static final byte[] TAG_KMC_20 = new byte[] { (byte)0x9F, (byte)0x40 };
	/**
	 * Retired Key Management Certificate 20 Private Key
	 */
	private static final byte[] TAG_KMK_20 = new byte[] { (byte)0x9F, (byte)0x41 };
	/**
	 * Cardholder Iris Images
	 */
	private static final byte[] TAG_CII = new byte[] { (byte)0x9F, (byte)0x42 };
	/**
	 * Biometric Information Templates Group Template
	 */
	private static final byte[] TAG_BITGT = new byte[] { (byte)0x9F, (byte)0x43 };
	/**
	 * Secure Messaging Certificate Signer
	 */
	private static final byte[] TAG_SMC = new byte[] { (byte)0x9F, (byte)0x44 };
	/**
	 * Secure Messaging Private Key
	 */
	private static final byte[] TAG_SMK = new byte[] { (byte)0x9F, (byte)0x45 };
	/**
	 * Pairing Code Reference Data
	 */
	private static final byte[] TAG_PCRD = new byte[] { (byte)0x9F, (byte)0x46 };
	/**
	 * CAK Proof of Possession Nonce
	 */
	private static final byte[] TAG_CPN = new byte[] { (byte)0x9F, (byte)0x47 };
	/**
	 * CAK Proof of Possession Signature
	 */
	private static final byte[] TAG_CPS = new byte[] { (byte)0x9F, (byte)0x48 };

	/*
	 * Lower tag half for switch/case statements
	 */
	/**
	 * Field ATSHB.
	 */
	private static final byte ATSHB = (byte)0x01;
	/**
	 * Field CPLC.
	 */
	private static final byte CPLC = (byte)0x02;
	/**
	 * Field CSN.
	 */
	private static final byte CSN = (byte)0x03;
	/**
	 * Field PCAP.
	 */
	private static final byte PCAP = (byte)0x04;
	/**
	 * Field PADMIN_KEY_TYPE.
	 */
	private static final byte PADMIN_KEY_TYPE = (byte)0x05;
	/**
	 * Field PADMIN_KEY.
	 */
	private static final byte PADMIN_KEY = (byte)0x06;
	/**
	 * Field CCC.
	 */
	private static final byte CCC = (byte)0x07;
	/**
	 * Field CHUID.
	 */
	private static final byte CHUID = (byte)0x08;
	/**
	 * Field PAC.
	 */
	private static final byte PAC = (byte)0x09;
	/**
	 * Field PAK.
	 */
	private static final byte PAK = (byte)0x0A;
	/**
	 * Field CHF.
	 */
	private static final byte CHF = (byte)0x0B;
	/**
	 * Field SO.
	 */
	private static final byte SO = (byte)0x0C;
	/**
	 * Field CFI.
	 */
	private static final byte CFI = (byte)0x0D;
	/**
	 * Field CAC.
	 */
	private static final byte CAC = (byte)0x0E;
	/**
	 * Field CAK.
	 */
	private static final byte CAK = (byte)0x0F;
	/**
	 * Field SYM_CAK_TYPE.
	 */
	private static final byte SYM_CAK_TYPE = (byte)0x10;
	/**
	 * Field SYM_CAK.
	 */
	private static final byte SYM_CAK = (byte)0x11;
	/**
	 * Field DSC.
	 */
	private static final byte DSC = (byte)0x12;
	/**
	 * Field DSK.
	 */
	private static final byte DSK = (byte)0x13;
	/**
	 * Field KMC.
	 */
	private static final byte KMC = (byte)0x14;
	/**
	 * Field KMK.
	 */
	private static final byte KMK = (byte)0x15;
	/**
	 * Field PI.
	 */
	private static final byte PI = (byte)0x16;
	/**
	 * Field DO.
	 */
	private static final byte DO = (byte)0x17;
	/**
	 * Field KHO.
	 */
	private static final byte KHO = (byte)0x18;
	/**
	 * Field KMC_01.
	 */
	private static final byte KMC_01 = (byte)0x1A;
	/**
	 * Field KMK_01.
	 */
	private static final byte KMK_01 = (byte)0x1B;
	/**
	 * Field KMC_02.
	 */
	private static final byte KMC_02 = (byte)0x1C;
	/**
	 * Field KMK_02.
	 */
	private static final byte KMK_02 = (byte)0x1D;
	/**
	 * Field KMC_03.
	 */
	private static final byte KMC_03 = (byte)0x1E;
	/**
	 * Field KMK_03.
	 */
	private static final byte KMK_03 = (byte)0x1F;
	/**
	 * Field KMC_04.
	 */
	private static final byte KMC_04 = (byte)0x20;
	/**
	 * Field KMK_04.
	 */
	private static final byte KMK_04 = (byte)0x21;
	/**
	 * Field KMC_05.
	 */
	private static final byte KMC_05 = (byte)0x22;
	/**
	 * Field KMK_05.
	 */
	private static final byte KMK_05 = (byte)0x23;
	/**
	 * Field KMC_06.
	 */
	private static final byte KMC_06 = (byte)0x24;
	/**
	 * Field KMK_06.
	 */
	private static final byte KMK_06 = (byte)0x25;
	/**
	 * Field KMC_07.
	 */
	private static final byte KMC_07 = (byte)0x26;
	/**
	 * Field KMK_07.
	 */
	private static final byte KMK_07 = (byte)0x27;
	/**
	 * Field KMC_08.
	 */
	private static final byte KMC_08 = (byte)0x28;
	/**
	 * Field KMK_08.
	 */
	private static final byte KMK_08 = (byte)0x29;
	/**
	 * Field KMC_09.
	 */
	private static final byte KMC_09 = (byte)0x2A;
	/**
	 * Field KMK_09.
	 */
	private static final byte KMK_09 = (byte)0x2B;
	/**
	 * Field KMC_10.
	 */
	private static final byte KMC_10 = (byte)0x2C;
	/**
	 * Field KMK_10.
	 */
	private static final byte KMK_10 = (byte)0x2D;
	/**
	 * Field KMC_11.
	 */
	private static final byte KMC_11 = (byte)0x2E;
	/**
	 * Field KMK_11.
	 */
	private static final byte KMK_11 = (byte)0x2F;
	/**
	 * Field KMC_12.
	 */
	private static final byte KMC_12 = (byte)0x30;
	/**
	 * Field KMK_12.
	 */
	private static final byte KMK_12 = (byte)0x31;
	/**
	 * Field KMC_13.
	 */
	private static final byte KMC_13 = (byte)0x32;
	/**
	 * Field KMK_13.
	 */
	private static final byte KMK_13 = (byte)0x33;
	/**
	 * Field KMC_14.
	 */
	private static final byte KMC_14 = (byte)0x34;
	/**
	 * Field KMK_14.
	 */
	private static final byte KMK_14 = (byte)0x35;
	/**
	 * Field KMC_15.
	 */
	private static final byte KMC_15 = (byte)0x36;
	/**
	 * Field KMK_15.
	 */
	private static final byte KMK_15 = (byte)0x37;
	/**
	 * Field KMC_16.
	 */
	private static final byte KMC_16 = (byte)0x38;
	/**
	 * Field KMK_16.
	 */
	private static final byte KMK_16 = (byte)0x39;
	/**
	 * Field KMC_17.
	 */
	private static final byte KMC_17 = (byte)0x3A;
	/**
	 * Field KMK_17.
	 */
	private static final byte KMK_17 = (byte)0x3B;
	/**
	 * Field KMC_18.
	 */
	private static final byte KMC_18 = (byte)0x3C;
	/**
	 * Field KMK_18.
	 */
	private static final byte KMK_18 = (byte)0x3D;
	/**
	 * Field KMC_19.
	 */
	private static final byte KMC_19 = (byte)0x3E;
	/**
	 * Field KMK_19.
	 */
	private static final byte KMK_19 = (byte)0x3F;
	/**
	 * Field KMC_20.
	 */
	private static final byte KMC_20 = (byte)0x40;
	/**
	 * Field KMK_20.
	 */
	private static final byte KMK_20 = (byte)0x41;
	/**
	 * Field CII.
	 */
	private static final byte CII = (byte)0x42;
	/**
	 * Field BITGT.
	 */
	private static final byte BITGT = (byte)0x43;
	/**
	 * Field SMC.
	 */
	private static final byte SMC = (byte)0x44;
	/**
	 * Field SMK.
	 */
	private static final byte SMK = (byte)0x45;
	/**
	 * Field PCRD.
	 */
	private static final byte PCRD = (byte)0x46;
	/**
	 * Field CPN.
	 */
	private static final byte CPN = (byte)0x47;
	/**
	 * Field CPS.
	 */
	private static final byte CPS = (byte)0x48;

	/*
	 * Data Variables Follow
	 */
	/**
	 * Field aTSHistoricalBytes.
	 */
	private byte[] aTSHistoricalBytes;
	/**
	 * Field cardProdLifecycle.
	 */
	private byte[] cardProdLifecycle;
	/**
	 * Field cSNuID.
	 */
	private byte[] cSNuID;
	/**
	 * Field applicationProperty.
	 */
	private PIVDataTempl applicationProperty;
	/**
	 * Field pAdminKeyType.
	 */
	private byte[] pAdminKeyType;
	/**
	 * Field pAdminKey.
	 */
	private Key pAdminKey;
	/**
	 * Field cardCapabilityCont.
	 */
	private PIVDataTempl cardCapabilityCont;
	/**
	 * Field cardHolderUniqueId.
	 */
	private PIVDataTempl cardHolderUniqueId;
	/**
	 * Field pIVAuthCertificate.
	 */
	private PIVDataTempl pIVAuthCertificate;
	/**
	 * Field pIVAuthPrivateKey.
	 */
	private Key pIVAuthPrivateKey;
	/**
	 * Field cardholderFingerprints.
	 */
	private PIVDataTempl cardholderFingerprints;
	/**
	 * Field securityObject.
	 */
	private PIVDataTempl securityObject;
	/**
	 * Field cardholderFacialImage.
	 */
	private PIVDataTempl cardholderFacialImage;
	/**
	 * Field cardAuthCertificate.
	 */
	private PIVDataTempl cardAuthCertificate;
	/**
	 * Field cardAuthPrivateKey.
	 */
	private Key cardAuthPrivateKey;
	/**
	 * Field cardAuthKeyType.
	 */
	private byte[] cardAuthKeyType;
	/**
	 * Field cardAuthSymKey.
	 */
	private Key cardAuthSymKey;
	/**
	 * Field digSigCertificate.
	 */
	private PIVDataTempl digSigCertificate;
	/**
	 * Field digSigPrivateKey.
	 */
	private Key digSigPrivateKey;
	/**
	 * Field keyMgmtCertificate.
	 */
	private PIVDataTempl keyMgmtCertificate;
	/**
	 * Field keyMgmtPrivateKey.
	 */
	private Key keyMgmtPrivateKey;
	/**
	 * Field printedInformation.
	 */
	private PIVDataTempl printedInformation;
	/**
	 * Field discoveryObject.
	 */
	private PIVDataTempl discoveryObject;
	/**
	 * Field keyHistoryObject.
	 */
	private PIVDataTempl keyHistoryObject;
	/**
	 * Field retiredKMCert01.
	 */
	private PIVDataTempl retiredKMCert01;
	/**
	 * Field retiredKMPrivKey01.
	 */
	private Key retiredKMPrivKey01;
	/**
	 * Field retiredKMCert02.
	 */
	private PIVDataTempl retiredKMCert02;
	/**
	 * Field retiredKMPrivKey02.
	 */
	private Key retiredKMPrivKey02;
	/**
	 * Field retiredKMCert03.
	 */
	private PIVDataTempl retiredKMCert03;
	/**
	 * Field retiredKMPrivKey03.
	 */
	private Key retiredKMPrivKey03;
	/**
	 * Field retiredKMCert04.
	 */
	private PIVDataTempl retiredKMCert04;
	/**
	 * Field retiredKMPrivKey04.
	 */
	private Key retiredKMPrivKey04;
	/**
	 * Field retiredKMCert05.
	 */
	private PIVDataTempl retiredKMCert05;
	/**
	 * Field retiredKMPrivKey05.
	 */
	private Key retiredKMPrivKey05;
	/**
	 * Field retiredKMCert06.
	 */
	private PIVDataTempl retiredKMCert06;
	/**
	 * Field retiredKMPrivKey06.
	 */
	private Key retiredKMPrivKey06;
	/**
	 * Field retiredKMCert07.
	 */
	private PIVDataTempl retiredKMCert07;
	/**
	 * Field retiredKMPrivKey07.
	 */
	private Key retiredKMPrivKey07;
	/**
	 * Field retiredKMCert08.
	 */
	private PIVDataTempl retiredKMCert08;
	/**
	 * Field retiredKMPrivKey08.
	 */
	private Key retiredKMPrivKey08;
	/**
	 * Field retiredKMCert09.
	 */
	private PIVDataTempl retiredKMCert09;
	/**
	 * Field retiredKMPrivKey09.
	 */
	private Key retiredKMPrivKey09;
	/**
	 * Field retiredKMCert10.
	 */
	private PIVDataTempl retiredKMCert10;
	/**
	 * Field retiredKMPrivKey10.
	 */
	private Key retiredKMPrivKey10;
	/**
	 * Field retiredKMCert11.
	 */
	private PIVDataTempl retiredKMCert11;
	/**
	 * Field retiredKMPrivKey11.
	 */
	private Key retiredKMPrivKey11;
	/**
	 * Field retiredKMCert12.
	 */
	private PIVDataTempl retiredKMCert12;
	/**
	 * Field retiredKMPrivKey12.
	 */
	private Key retiredKMPrivKey12;
	/**
	 * Field retiredKMCert13.
	 */
	private PIVDataTempl retiredKMCert13;
	/**
	 * Field retiredKMPrivKey13.
	 */
	private Key retiredKMPrivKey13;
	/**
	 * Field retiredKMCert14.
	 */
	private PIVDataTempl retiredKMCert14;
	/**
	 * Field retiredKMPrivKey14.
	 */
	private Key retiredKMPrivKey14;
	/**
	 * Field retiredKMCert15.
	 */
	private PIVDataTempl retiredKMCert15;
	/**
	 * Field retiredKMPrivKey15.
	 */
	private Key retiredKMPrivKey15;
	/**
	 * Field retiredKMCert16.
	 */
	private PIVDataTempl retiredKMCert16;
	/**
	 * Field retiredKMPrivKey16.
	 */
	private Key retiredKMPrivKey16;
	/**
	 * Field retiredKMCert17.
	 */
	private PIVDataTempl retiredKMCert17;
	/**
	 * Field retiredKMPrivKey17.
	 */
	private Key retiredKMPrivKey17;
	/**
	 * Field retiredKMCert18.
	 */
	private PIVDataTempl retiredKMCert18;
	/**
	 * Field retiredKMPrivKey18.
	 */
	private Key retiredKMPrivKey18;
	/**
	 * Field retiredKMCert19.
	 */
	private PIVDataTempl retiredKMCert19;
	/**
	 * Field retiredKMPrivKey19.
	 */
	private Key retiredKMPrivKey19;
	/**
	 * Field retiredKMCert20.
	 */
	private PIVDataTempl retiredKMCert20;
	/**
	 * Field retiredKMPrivKey20.
	 */
	private Key retiredKMPrivKey20;
	/**
	 * Field cardholderIrisImages.
	 */
	private PIVDataTempl cardholderIrisImages;
	/**
	 * Field bioInfoTemplGrpTempl.
	 */
	private PIVDataTempl bioInfoTemplGrpTempl;
	/**
	 * Field secMessagingCertSigner.
	 */
	private PIVDataTempl secMessagingCertSigner;
	/**
	 * Field secMessagingPrivKey.
	 */
	private Key secMessagingPrivKey;
	/**
	 * Field pairingCodeReferenceData.
	 */
	private PIVDataTempl pairingCodeReferenceData;
	/**
	 * CAK Proof of Possession Nonce
	 */
	private byte[] cakPopNonce;
	/**
	 * CAK Proof of Possession Signature
	 */
	private byte[] cakPopSig;

	/**
	 * Field KEY_SYMMETRIC_3DES.
	 * (value is 0)
	 */
	private static final int KEY_SYMMETRIC_3DES = 0;
	/**
	 * Field KEY_SYMMETRIC_AES.
	 * (value is 1)
	 */
	private static final int KEY_SYMMETRIC_AES = 1;
	/**
	 * Field KEY_ASYMMETRIC_RSA.
	 * (value is 2)
	 */
	private static final int KEY_ASYMMETRIC_RSA = 2;
	/**
	 * Field KEY_ASYMMETRIC_ECC.
	 * (value is 3)
	 */
	private static final int KEY_ASYMMETRIC_ECC = 3;
	/**
	 * Field KEY_ASYMMETRIC_DSA.
	 * (value is 4)
	 */
	private static final int KEY_ASYMMETRIC_DSA = 4;
	/**
	 * Field carddata.
	 */
	private byte[] carddata;
	/**
	 * Field debug.
	 */
	private boolean debug = false;
	
	/**
	 * Constructor for CardData80073.
	 */
	public CardData80073() {
		/*
		 * Empty constructor.  Any null item will not be encoded,
		 * and any item not decoded will be null.  Any getter method
		 * will return null, or the object contents.
		 */
	}
	
	/**
	 * Constructor for CardData80073.
	 * @param carddata byte[]
	 */
	public CardData80073(byte[] carddata) {
		this.carddata = carddata;
		this.decode();
	}

	/**
	 * Method toByteArray.
	 * @return byte[]
	 */
	public byte[] toByteArray() {
		this.encode();
		return carddata;
	}


	/**
	 * Method digestString.
	 * @return String
	 */
	public String digestString() {
		return DataUtil.byteArrayToString(DigestEngine.sHA1Sum(this.toByteArray()));
	}

	/**
	 * Method encode.
	 */
	private void encode() {
		//BER-TLV Encode all of the globals and then set cardData as the result
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		try {
			//ATS Historical Bytes
			if (null != this.aTSHistoricalBytes) {
				TLV _hbtlv = BERTLVFactory.encodeTLV(new Tag(TAG_ATSHB), this.aTSHistoricalBytes);
				if (debug) { System.out.println("Encoding HB: " + DataUtil.byteArrayToString(_hbtlv.getBytes())); }
				baos.write(_hbtlv.getBytes());
			}
			//CPLC
			if (null != this.cardProdLifecycle) {
				TLV _cplctlv = BERTLVFactory.encodeTLV(new Tag(TAG_CPLC), this.cardProdLifecycle);
				if (debug) { System.out.println("Encoding CPLC: " + DataUtil.byteArrayToString(_cplctlv.getBytes())); }
				baos.write(_cplctlv.getBytes());
			}
			//CSN
			if (null != this.cSNuID) {
				TLV _csntlv = BERTLVFactory.encodeTLV(new Tag(TAG_CSN), this.cSNuID);
				if (debug) { System.out.println("Encoding CSN: " + DataUtil.byteArrayToString(_csntlv.getBytes())); }
				baos.write(_csntlv.getBytes());
			}
			//PCAP
			if (null != this.applicationProperty) {
				TLV _pcaptlv = BERTLVFactory.encodeTLV(new Tag(TAG_PCAP), this.applicationProperty.getEncoded());
				if (debug) { System.out.println("Encoding PCAP: " + DataUtil.byteArrayToString(_pcaptlv.getBytes())); }
				baos.write(_pcaptlv.getBytes());
			}
			//PIV Admin Key & Key Type
			if (null != this.pAdminKey) {
				//Encode type first
				TLV _padmkttlv = BERTLVFactory.encodeTLV(new Tag(TAG_PADMIN_KEY_TYPE), this.pAdminKeyType);
				if (debug) { System.out.println("Encoding PIV Admin Symmetric Key Type: " + DataUtil.byteArrayToString(_padmkttlv.getBytes())); }
				baos.write(_padmkttlv.getBytes());
				//Encode key
				TLV _padmktlv = BERTLVFactory.encodeTLV(new Tag(TAG_PADMIN_KEY), this.pAdminKey.getEncoded());
				if (debug) { System.out.println("Encoding CAK Symmetric: " + DataUtil.byteArrayToString(_padmktlv.getBytes())); }
				baos.write(_padmktlv.getBytes());
			}
			//CCC
			if (null != this.cardCapabilityCont) {
				TLV _ccctlv = BERTLVFactory.encodeTLV(new Tag(TAG_CCC), this.cardCapabilityCont.getEncoded());
				if (debug) { System.out.println("Encoding CCC: " + DataUtil.byteArrayToString(_ccctlv.getBytes())); }
				baos.write(_ccctlv.getBytes());
			}
			//CHUID
			if (null != this.cardHolderUniqueId) {
				TLV _chuidtlv = BERTLVFactory.encodeTLV(new Tag(TAG_CHUID), this.cardHolderUniqueId.getEncoded());
				if (debug) { System.out.println("Encoding CHUID: " + DataUtil.byteArrayToString(_chuidtlv.getBytes())); }
				baos.write(_chuidtlv.getBytes());
			}
			//PAC
			if (null != this.pIVAuthCertificate) {
				TLV _pactlv = BERTLVFactory.encodeTLV(new Tag(TAG_PAC), this.pIVAuthCertificate.getEncoded());
				if (debug) { System.out.println("Encoding PAC: " + DataUtil.byteArrayToString(_pactlv.getBytes())); }
				baos.write(_pactlv.getBytes());
			}
			//PAK
			if (null != this.pIVAuthPrivateKey) {
				TLV _paktlv = BERTLVFactory.encodeTLV(new Tag(TAG_PAK), this.pIVAuthPrivateKey.getEncoded());
				if (debug) { System.out.println("Encoding PAK Private: " + DataUtil.byteArrayToString(_paktlv.getBytes())); }
				baos.write(_paktlv.getBytes());
			}
			//CHF
			if (null != this.cardholderFingerprints) {
				TLV _chftlv = BERTLVFactory.encodeTLV(new Tag(TAG_CHF), this.cardholderFingerprints.getEncoded());
				if (debug) { System.out.println("Encoding CHF: " + DataUtil.byteArrayToString(_chftlv.getBytes())); }
				baos.write(_chftlv.getBytes());
			}
			//SO
			if (null != this.securityObject) {
				TLV _sotlv = BERTLVFactory.encodeTLV(new Tag(TAG_SO), this.securityObject.getEncoded());
				if (debug) { System.out.println("Encoding SO: " + DataUtil.byteArrayToString(_sotlv.getBytes())); }
				baos.write(_sotlv.getBytes());
			}
			//CFI
			if (null != this.cardholderFacialImage) {
				TLV _cfitlv = BERTLVFactory.encodeTLV(new Tag(TAG_CFI), this.cardholderFacialImage.getEncoded());
				if (debug) { System.out.println("Encoding CFI: " + DataUtil.byteArrayToString(_cfitlv.getBytes())); }
				baos.write(_cfitlv.getBytes());
			}
			//CardAuth Cert
			if (null != this.cardAuthCertificate) {
				TLV _cactlv = BERTLVFactory.encodeTLV(new Tag(TAG_CAC), this.cardAuthCertificate.getEncoded());
				if (debug) { System.out.println("Encoding CAC: " + DataUtil.byteArrayToString(_cactlv.getBytes())); }
				baos.write(_cactlv.getBytes());
			}
			//CardAuth Private Key
			if (null != this.cardAuthPrivateKey) {
				TLV _cakatlv = BERTLVFactory.encodeTLV(new Tag(TAG_CAK), this.cardAuthPrivateKey.getEncoded());
				if (debug) { System.out.println("Encoding CAK Private: " + DataUtil.byteArrayToString(_cakatlv.getBytes())); }
				baos.write(_cakatlv.getBytes());
			}
			//CardAuth Symmetric Key & Type
			if (null != this.cardAuthSymKey) {
				//Encode type first
				TLV _caksttlv = BERTLVFactory.encodeTLV(new Tag(TAG_SYM_CAK_TYPE), this.cardAuthKeyType);
				if (debug) { System.out.println("Encoding CAK Symmetric Key Type: " + DataUtil.byteArrayToString(_caksttlv.getBytes())); }
				baos.write(_caksttlv.getBytes());
				//Encode key
				TLV _cakstlv = BERTLVFactory.encodeTLV(new Tag(TAG_SYM_CAK), this.cardAuthSymKey.getEncoded());
				if (debug) { System.out.println("Encoding CAK Symmetric: " + DataUtil.byteArrayToString(_cakstlv.getBytes())); }
				baos.write(_cakstlv.getBytes());
			}
			//DSC
			if (null != this.digSigCertificate) {
				TLV _dsctlv = BERTLVFactory.encodeTLV(new Tag(TAG_DSC), this.digSigCertificate.getEncoded());
				if (debug) { System.out.println("Encoding DSC: " + DataUtil.byteArrayToString(_dsctlv.getBytes())); }
				baos.write(_dsctlv.getBytes());
			}
			//DSK
			if (null != this.digSigPrivateKey) {
				TLV _dsktlv = BERTLVFactory.encodeTLV(new Tag(TAG_DSK), this.digSigPrivateKey.getEncoded());
				if (debug) { System.out.println("Encoding DSK: " + DataUtil.byteArrayToString(_dsktlv.getBytes())); }
				baos.write(_dsktlv.getBytes());
			}
			//KMC
			if (null != this.keyMgmtCertificate) {
				TLV _kmctlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC), this.keyMgmtCertificate.getEncoded());
				if (debug) { System.out.println("Encoding KMC: " + DataUtil.byteArrayToString(_kmctlv.getBytes())); }
				baos.write(_kmctlv.getBytes());
			}
			//KMK
			if (null != this.keyMgmtPrivateKey) {
				TLV _kmktlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK), this.keyMgmtPrivateKey.getEncoded());
				if (debug) { System.out.println("Encoding KMK: " + DataUtil.byteArrayToString(_kmktlv.getBytes())); }
				baos.write(_kmktlv.getBytes());
			}
			//PI
			if (null != this.printedInformation) {
				TLV _pitlv = BERTLVFactory.encodeTLV(new Tag(TAG_PI), this.printedInformation.getEncoded());
				if (debug) { System.out.println("Encoding PI: " + DataUtil.byteArrayToString(_pitlv.getBytes())); }
				baos.write(_pitlv.getBytes());
			}
			//PDO
			if (this.discoveryObject != null) {
				TLV _pdotlv = BERTLVFactory.encodeTLV(new Tag(TAG_DO), this.discoveryObject.getEncoded());
				if (debug) { System.out.println("Encoding DO: " + DataUtil.byteArrayToString(_pdotlv.getBytes())); }
				baos.write(_pdotlv.getBytes());
			}
			//KHO
			if (this.keyHistoryObject != null) {
				TLV _khotlv = BERTLVFactory.encodeTLV(new Tag(TAG_KHO), this.keyHistoryObject.getEncoded());
				if (debug) { System.out.println("Encoding KHO: " + DataUtil.byteArrayToString(_khotlv.getBytes())); }
				baos.write(_khotlv.getBytes());
			}
			//KMC 01
			if (this.retiredKMCert01 != null) {
				TLV _kmc01tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_01), this.retiredKMCert01.getEncoded());
				if (debug) { System.out.println("Encoding KMC 01: " + DataUtil.byteArrayToString(_kmc01tlv.getBytes())); }
				baos.write(_kmc01tlv.getBytes());
			}
			//KMK 01
			if (this.retiredKMPrivKey01 != null) {
				TLV _kmk01tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_01), this.retiredKMPrivKey01.getEncoded());
				if (debug) { System.out.println("Encoding KMK 01: " + DataUtil.byteArrayToString(_kmk01tlv.getBytes())); }
				baos.write(_kmk01tlv.getBytes());
			}
			//KMC 02
			if (this.retiredKMCert02 != null) {
				TLV _kmc02tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_02), this.retiredKMCert02.getEncoded());
				if (debug) { System.out.println("Encoding KMC 02: " + DataUtil.byteArrayToString(_kmc02tlv.getBytes())); }
				baos.write(_kmc02tlv.getBytes());
			}
			//KMK 02
			if (this.retiredKMPrivKey02 != null) {
				TLV _kmk02tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_02), this.retiredKMPrivKey02.getEncoded());
				if (debug) { System.out.println("Encoding KMK 02: " + DataUtil.byteArrayToString(_kmk02tlv.getBytes())); }
				baos.write(_kmk02tlv.getBytes());
			}
			//KMC 03
			if (this.retiredKMCert03 != null) {
				TLV _kmc03tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_03), this.retiredKMCert03.getEncoded());
				if (debug) { System.out.println("Encoding KMC 03: " + DataUtil.byteArrayToString(_kmc03tlv.getBytes())); }
				baos.write(_kmc03tlv.getBytes());
			}
			//KMK 03
			if (this.retiredKMPrivKey03 != null) {
				TLV _kmk03tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_03), this.retiredKMPrivKey03.getEncoded());
				if (debug) { System.out.println("Encoding KMK 03: " + DataUtil.byteArrayToString(_kmk03tlv.getBytes())); }
				baos.write(_kmk03tlv.getBytes());
			}
			//KMC 04
			if (this.retiredKMCert04 != null) {
				TLV _kmc04tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_04), this.retiredKMCert04.getEncoded());
				if (debug) { System.out.println("Encoding KMC 04: " + DataUtil.byteArrayToString(_kmc04tlv.getBytes())); }
				baos.write(_kmc04tlv.getBytes());
			}
			//KMK 04
			if (this.retiredKMPrivKey04 != null) {
				TLV _kmk04tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_04), this.retiredKMPrivKey04.getEncoded());
				if (debug) { System.out.println("Encoding KMK 04: " + DataUtil.byteArrayToString(_kmk04tlv.getBytes())); }
				baos.write(_kmk04tlv.getBytes());
			}
			//KMC 05
			if (this.retiredKMCert05 != null) {
				TLV _kmc05tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_05), this.retiredKMCert05.getEncoded());
				if (debug) { System.out.println("Encoding KMC 05: " + DataUtil.byteArrayToString(_kmc05tlv.getBytes())); }
				baos.write(_kmc05tlv.getBytes());
			}
			//KMK 05
			if (this.retiredKMPrivKey05 != null) {
				TLV _kmk05tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_05), this.retiredKMPrivKey05.getEncoded());
				if (debug) { System.out.println("Encoding KMK 05: " + DataUtil.byteArrayToString(_kmk05tlv.getBytes())); }
				baos.write(_kmk05tlv.getBytes());
			}
			//KMC 06
			if (this.retiredKMCert06 != null) {
				TLV _kmc06tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_06), this.retiredKMCert06.getEncoded());
				if (debug) { System.out.println("Encoding KMC 06: " + DataUtil.byteArrayToString(_kmc06tlv.getBytes())); }
				baos.write(_kmc06tlv.getBytes());
			}
			//KMK 06
			if (this.retiredKMPrivKey06 != null) {
				TLV _kmk06tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_06), this.retiredKMPrivKey06.getEncoded());
				if (debug) { System.out.println("Encoding KMK 06: " + DataUtil.byteArrayToString(_kmk06tlv.getBytes())); }
				baos.write(_kmk06tlv.getBytes());
			}
			//KMC 07
			if (this.retiredKMCert07 != null) {
				TLV _kmc07tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_07), this.retiredKMCert07.getEncoded());
				if (debug) { System.out.println("Encoding KMC 07: " + DataUtil.byteArrayToString(_kmc07tlv.getBytes())); }
				baos.write(_kmc07tlv.getBytes());
			}
			//KMK 07
			if (this.retiredKMPrivKey07 != null) {
				TLV _kmk07tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_07), this.retiredKMPrivKey07.getEncoded());
				if (debug) { System.out.println("Encoding KMK 07: " + DataUtil.byteArrayToString(_kmk07tlv.getBytes())); }
				baos.write(_kmk07tlv.getBytes());
			}
			//KMC 08
			if (this.retiredKMCert08 != null) {
				TLV _kmc08tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_08), this.retiredKMCert08.getEncoded());
				if (debug) { System.out.println("Encoding KMC 08: " + DataUtil.byteArrayToString(_kmc08tlv.getBytes())); }
				baos.write(_kmc08tlv.getBytes());
			}
			//KMK 08
			if (this.retiredKMPrivKey08 != null) {
				TLV _kmk08tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_08), this.retiredKMPrivKey08.getEncoded());
				if (debug) { System.out.println("Encoding KMK 08: " + DataUtil.byteArrayToString(_kmk08tlv.getBytes())); }
				baos.write(_kmk08tlv.getBytes());
			}
			//KMC 09
			if (this.retiredKMCert09 != null) {
				TLV _kmc09tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_09), this.retiredKMCert09.getEncoded());
				if (debug) { System.out.println("Encoding KMC 09: " + DataUtil.byteArrayToString(_kmc09tlv.getBytes())); }
				baos.write(_kmc09tlv.getBytes());
			}
			//KMK 09
			if (this.retiredKMPrivKey09 != null) {
				TLV _kmk09tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_09), this.retiredKMPrivKey09.getEncoded());
				if (debug) { System.out.println("Encoding KMK 09: " + DataUtil.byteArrayToString(_kmk09tlv.getBytes())); }
				baos.write(_kmk09tlv.getBytes());
			}
			//KMC 10
			if (this.retiredKMCert10 != null) {
				TLV _kmc10tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_10), this.retiredKMCert10.getEncoded());
				if (debug) { System.out.println("Encoding KMC 10: " + DataUtil.byteArrayToString(_kmc10tlv.getBytes())); }
				baos.write(_kmc10tlv.getBytes());
			}
			//KMK 10
			if (this.retiredKMPrivKey10 != null) {
				TLV _kmk10tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_10), this.retiredKMPrivKey10.getEncoded());
				if (debug) { System.out.println("Encoding KMK 10: " + DataUtil.byteArrayToString(_kmk10tlv.getBytes())); }
				baos.write(_kmk10tlv.getBytes());
			}
			//KMC 11
			if (this.retiredKMCert11 != null) {
				TLV _kmc11tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_11), this.retiredKMCert11.getEncoded());
				if (debug) { System.out.println("Encoding KMC 11: " + DataUtil.byteArrayToString(_kmc11tlv.getBytes())); }
				baos.write(_kmc11tlv.getBytes());
			}
			//KMK 11
			if (this.retiredKMPrivKey11 != null) {
				TLV _kmk11tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_11), this.retiredKMPrivKey11.getEncoded());
				if (debug) { System.out.println("Encoding KMK 11: " + DataUtil.byteArrayToString(_kmk11tlv.getBytes())); }
				baos.write(_kmk11tlv.getBytes());
			}
			//KMC 12
			if (this.retiredKMCert12 != null) {
				TLV _kmc12tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_12), this.retiredKMCert12.getEncoded());
				if (debug) { System.out.println("Encoding KMC 12: " + DataUtil.byteArrayToString(_kmc12tlv.getBytes())); }
				baos.write(_kmc12tlv.getBytes());
			}
			//KMK 12
			if (this.retiredKMPrivKey12 != null) {
				TLV _kmk12tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_12), this.retiredKMPrivKey12.getEncoded());
				if (debug) { System.out.println("Encoding KMK 12: " + DataUtil.byteArrayToString(_kmk12tlv.getBytes())); }
				baos.write(_kmk12tlv.getBytes());
			}
			//KMC 13
			if (this.retiredKMCert13 != null) {
				TLV _kmc13tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_13), this.retiredKMCert13.getEncoded());
				if (debug) { System.out.println("Encoding KMC 13: " + DataUtil.byteArrayToString(_kmc13tlv.getBytes())); }
				baos.write(_kmc13tlv.getBytes());
			}
			//KMK 13
			if (this.retiredKMPrivKey13 != null) {
				TLV _kmk13tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_13), this.retiredKMPrivKey13.getEncoded());
				if (debug) { System.out.println("Encoding KMK 13: " + DataUtil.byteArrayToString(_kmk13tlv.getBytes())); }
				baos.write(_kmk13tlv.getBytes());
			}
			//KMC 14
			if (this.retiredKMCert14 != null) {
				TLV _kmc14tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_14), this.retiredKMCert14.getEncoded());
				if (debug) { System.out.println("Encoding KMC 14: " + DataUtil.byteArrayToString(_kmc14tlv.getBytes())); }
				baos.write(_kmc14tlv.getBytes());
			}
			//KMK 14
			if (this.retiredKMPrivKey14 != null) {
				TLV _kmk14tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_14), this.retiredKMPrivKey14.getEncoded());
				if (debug) { System.out.println("Encoding KMK 14: " + DataUtil.byteArrayToString(_kmk14tlv.getBytes())); }
				baos.write(_kmk14tlv.getBytes());
			}
			//KMC 15
			if (this.retiredKMCert15 != null) {
				TLV _kmc15tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_15), this.retiredKMCert15.getEncoded());
				if (debug) { System.out.println("Encoding KMC 15: " + DataUtil.byteArrayToString(_kmc15tlv.getBytes())); }
				baos.write(_kmc15tlv.getBytes());
			}
			//KMK 15
			if (this.retiredKMPrivKey15 != null) {
				TLV _kmk15tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_15), this.retiredKMPrivKey15.getEncoded());
				if (debug) { System.out.println("Encoding KMK 15: " + DataUtil.byteArrayToString(_kmk15tlv.getBytes())); }
				baos.write(_kmk15tlv.getBytes());
			}
			//KMC 16
			if (this.retiredKMCert16 != null) {
				TLV _kmc16tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_16), this.retiredKMCert16.getEncoded());
				if (debug) { System.out.println("Encoding KMC 16: " + DataUtil.byteArrayToString(_kmc16tlv.getBytes())); }
				baos.write(_kmc16tlv.getBytes());
			}
			//KMK 16
			if (this.retiredKMPrivKey16 != null) {
				TLV _kmk16tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_16), this.retiredKMPrivKey16.getEncoded());
				if (debug) { System.out.println("Encoding KMK 16: " + DataUtil.byteArrayToString(_kmk16tlv.getBytes())); }
				baos.write(_kmk16tlv.getBytes());
			}
			//KMC 17
			if (this.retiredKMCert17 != null) {
				TLV _kmc17tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_17), this.retiredKMCert17.getEncoded());
				if (debug) { System.out.println("Encoding KMC 17: " + DataUtil.byteArrayToString(_kmc17tlv.getBytes())); }
				baos.write(_kmc17tlv.getBytes());
			}
			//KMK 17
			if (this.retiredKMPrivKey17 != null) {
				TLV _kmk17tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_17), this.retiredKMPrivKey17.getEncoded());
				if (debug) { System.out.println("Encoding KMK 17: " + DataUtil.byteArrayToString(_kmk17tlv.getBytes())); }
				baos.write(_kmk17tlv.getBytes());
			}
			//KMC 18
			if (this.retiredKMCert18 != null) {
				TLV _kmc18tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_18), this.retiredKMCert18.getEncoded());
				if (debug) { System.out.println("Encoding KMC 18: " + DataUtil.byteArrayToString(_kmc18tlv.getBytes())); }
				baos.write(_kmc18tlv.getBytes());
			}
			//KMK 18
			if (this.retiredKMPrivKey18 != null) {
				TLV _kmk18tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_18), this.retiredKMPrivKey18.getEncoded());
				if (debug) { System.out.println("Encoding KMK 18: " + DataUtil.byteArrayToString(_kmk18tlv.getBytes())); }
				baos.write(_kmk18tlv.getBytes());
			}
			//KMC 19
			if (this.retiredKMCert19 != null) {
				TLV _kmc19tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_19), this.retiredKMCert19.getEncoded());
				if (debug) { System.out.println("Encoding KMC 19: " + DataUtil.byteArrayToString(_kmc19tlv.getBytes())); }
				baos.write(_kmc19tlv.getBytes());
			}
			//KMK 19
			if (this.retiredKMPrivKey19 != null) {
				TLV _kmk19tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_19), this.retiredKMPrivKey19.getEncoded());
				if (debug) { System.out.println("Encoding KMK 19: " + DataUtil.byteArrayToString(_kmk19tlv.getBytes())); }
				baos.write(_kmk19tlv.getBytes());
			}
			//KMC 20
			if (this.retiredKMCert20 != null) {
				TLV _kmc20tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMC_20), this.retiredKMCert20.getEncoded());
				if (debug) { System.out.println("Encoding KMC 20: " + DataUtil.byteArrayToString(_kmc20tlv.getBytes())); }
				baos.write(_kmc20tlv.getBytes());
			}
			//KMK 20
			if (this.retiredKMPrivKey20 != null) {
				TLV _kmk20tlv = BERTLVFactory.encodeTLV(new Tag(TAG_KMK_20), this.retiredKMPrivKey20.getEncoded());
				if (debug) { System.out.println("Encoding KMK 20: " + DataUtil.byteArrayToString(_kmk20tlv.getBytes())); }
				baos.write(_kmk20tlv.getBytes());
			}
			//CII
			if (this.cardholderIrisImages != null) {
				TLV _ciitlv = BERTLVFactory.encodeTLV(new Tag(TAG_CII), this.cardholderIrisImages.getEncoded());
				if (debug) { System.out.println("Encoding CII: " + DataUtil.byteArrayToString(_ciitlv.getBytes())); }
				baos.write(_ciitlv.getBytes());
			}
			//BITGT
			if (this.bioInfoTemplGrpTempl != null) {
				TLV _bittlv = BERTLVFactory.encodeTLV(new Tag(TAG_BITGT), this.bioInfoTemplGrpTempl.getEncoded());
				if (debug) { System.out.println("Encoding BITGT: " + DataUtil.byteArrayToString(_bittlv.getBytes())); }
				baos.write(_bittlv.getBytes());
			}
			//SMC
			if (this.secMessagingCertSigner != null) {
				TLV _smctlv = BERTLVFactory.encodeTLV(new Tag(TAG_SMC), this.secMessagingCertSigner.getEncoded());
				if (debug) { System.out.println("Encoding SMC: " + DataUtil.byteArrayToString(_smctlv.getBytes())); }
				baos.write(_smctlv.getBytes());
			}
			//SMK
			if (this.secMessagingPrivKey != null) {
				TLV _smktlv = BERTLVFactory.encodeTLV(new Tag(TAG_SMK), this.secMessagingPrivKey.getEncoded());
				if (debug) { System.out.println("Encoding SMK: " + DataUtil.byteArrayToString(_smktlv.getBytes())); }
				baos.write(_smktlv.getBytes());
			}
			//PCRD
			if (this.pairingCodeReferenceData != null) {
				TLV _pcrdtlv = BERTLVFactory.encodeTLV(new Tag(TAG_PCRD), this.pairingCodeReferenceData.getEncoded());
				if (debug) { System.out.println("Encoding PCRD: " + DataUtil.byteArrayToString(_pcrdtlv.getBytes())); }
				baos.write(_pcrdtlv.getBytes());
			}
			//CPN
			if (this.cakPopNonce != null) {
				TLV _cpntlv = BERTLVFactory.encodeTLV(new Tag(TAG_CPN), cakPopNonce);
				if (debug) { System.out.println("Encoding CAK PoP Nonce: " + DataUtil.byteArrayToString(_cpntlv.getBytes())); }
				baos.write(_cpntlv.getBytes());
			}
			//CPS
			if (this.cakPopSig != null) {
				TLV _cpstlv = BERTLVFactory.encodeTLV(new Tag(TAG_CPS), cakPopSig);
				if (debug) { System.out.println("Encoding CAK PoP Sig: " + DataUtil.byteArrayToString(_cpstlv.getBytes())); }
				baos.write(_cpstlv.getBytes());
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		this.carddata = baos.toByteArray();
	}

	/**
	 * Method decode.
	 */
	private void decode() {
		//Decode the BER-TLV structure in cardData
		Enumeration<?> children = BERTLVFactory.decodeTLV(carddata);
		while (children.hasMoreElements()) {

			TLV child_tlv = (TLV) children.nextElement();
			Tag child_tag = child_tlv.getTag();
			byte[] value = child_tlv.getValue();

			switch (child_tag.getBytes()[1]) {
				case ATSHB: {
					this.aTSHistoricalBytes = value;
					if (debug) { System.out.println("Decoding HB: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CPLC: {
					this.cardProdLifecycle = value;
					if (debug) { System.out.println("Decoding CPLC: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CSN: {
					this.cSNuID = value;
					if (debug) { System.out.println("Decoding CSN: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case PCAP: {
					this.applicationProperty = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding PCAP: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case PADMIN_KEY_TYPE: {
					this.pAdminKeyType = value;
					break;
				}
				case PADMIN_KEY: {
					this.pAdminKey = this.keyFromBytes(value, keyTypeFromBA(this.pAdminKeyType));
					break;
				}
				case CCC: {
					this.cardCapabilityCont = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding CCC: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CHUID: {
					this.cardHolderUniqueId = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding CHUID: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case PAC: {
					this.pIVAuthCertificate = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding PIV Auth Cert: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case PAK: {
					this.pIVAuthPrivateKey = keyFromBytes(value, getKeyType(this.pIVAuthCertificate));
					if (debug) { System.out.println("Decoding PIV Auth Priv: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CHF: {
					this.cardholderFingerprints = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Cardholder Fingerprints: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case SO: {
					this.securityObject = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Security Object: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CFI: {
					this.cardholderFacialImage = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Cardholder Facial Image: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CAC: {
					this.cardAuthCertificate = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding CAC: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CAK: {
					this.cardAuthPrivateKey = keyFromBytes(value, getKeyType(this.cardAuthCertificate));
					if (debug) { System.out.println("Decoding CAK Private: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case SYM_CAK_TYPE: {
					this.cardAuthKeyType = value;
					break;
				}
				case SYM_CAK: {
					this.cardAuthSymKey = this.keyFromBytes(value, keyTypeFromBA(this.cardAuthKeyType));
					break;
				}
				case DSC: {
					this.digSigCertificate = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Signature Certificate: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case DSK: {
					this.digSigPrivateKey = keyFromBytes(value, getKeyType(this.digSigCertificate));
					if (debug) { System.out.println("Decoding Signature Priv: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC: {
					this.keyMgmtCertificate = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding KM Certificate: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK: {
					this.keyMgmtPrivateKey = keyFromBytes(value, getKeyType(this.keyMgmtCertificate));
					if (debug) { System.out.println("Decoding KM Priv: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case PI: {
					this.printedInformation = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Printed Information: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case DO: {
					this.discoveryObject = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding DO: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KHO: {
					this.keyHistoryObject = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Key History Object: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_01: {
					this.retiredKMCert01 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 01: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_01: {
					this.retiredKMPrivKey01 = keyFromBytes(value, getKeyType(this.retiredKMCert01));
					if (debug) { System.out.println("Decoding Retired Priv 01: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_02: {
					this.retiredKMCert02 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 02: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_02: {
					this.retiredKMPrivKey02 = keyFromBytes(value, getKeyType(this.retiredKMCert02));
					if (debug) { System.out.println("Decoding Retired Priv 02: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_03: {
					this.retiredKMCert03 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 03: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_03: {
					this.retiredKMPrivKey03 = keyFromBytes(value, getKeyType(this.retiredKMCert03));
					if (debug) { System.out.println("Decoding Retired Priv 03: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_04: {
					this.retiredKMCert04 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 04: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_04: {
					this.retiredKMPrivKey04 = keyFromBytes(value, getKeyType(this.retiredKMCert04));
					if (debug) { System.out.println("Decoding Retired Priv 04: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_05: {
					this.retiredKMCert05 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 05: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_05: {
					this.retiredKMPrivKey05 = keyFromBytes(value, getKeyType(this.retiredKMCert05));
					if (debug) { System.out.println("Decoding Retired Priv 05: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_06: {
					this.retiredKMCert06 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 06: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_06: {
					this.retiredKMPrivKey06 = keyFromBytes(value, getKeyType(this.retiredKMCert06));
					if (debug) { System.out.println("Decoding Retired Priv 06: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_07: {
					this.retiredKMCert07 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 07: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_07: {
					this.retiredKMPrivKey07 = keyFromBytes(value, getKeyType(this.retiredKMCert07));
					if (debug) { System.out.println("Decoding Retired Priv 07: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_08: {
					this.retiredKMCert08 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 08: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_08: {
					this.retiredKMPrivKey08 = keyFromBytes(value, getKeyType(this.retiredKMCert08));
					if (debug) { System.out.println("Decoding Retired Priv 08: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_09: {
					this.retiredKMCert09 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 09: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_09: {
					this.retiredKMPrivKey09 = keyFromBytes(value, getKeyType(this.retiredKMCert09));
					if (debug) { System.out.println("Decoding Retired Priv 09: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_10: {
					this.retiredKMCert10 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 10: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_10: {
					this.retiredKMPrivKey10 = keyFromBytes(value, getKeyType(this.retiredKMCert10));
					if (debug) { System.out.println("Decoding Retired Priv 10: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_11: {
					this.retiredKMCert11 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 11: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_11: {
					this.retiredKMPrivKey11 = keyFromBytes(value, getKeyType(this.retiredKMCert11));
					if (debug) { System.out.println("Decoding Retired Priv 11: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_12: {
					this.retiredKMCert12 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 12: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_12: {
					this.retiredKMPrivKey12 = keyFromBytes(value, getKeyType(this.retiredKMCert12));
					if (debug) { System.out.println("Decoding Retired Priv 12: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_13: {
					this.retiredKMCert13 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 13: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_13: {
					this.retiredKMPrivKey13 = keyFromBytes(value, getKeyType(this.retiredKMCert13));
					if (debug) { System.out.println("Decoding Retired Priv 13: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_14: {
					this.retiredKMCert14 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 14: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_14: {
					this.retiredKMPrivKey14 = keyFromBytes(value, getKeyType(this.retiredKMCert14));
					if (debug) { System.out.println("Decoding Retired Priv 14: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_15: {
					this.retiredKMCert15 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 15: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_15: {
					this.retiredKMPrivKey15 = keyFromBytes(value, getKeyType(this.retiredKMCert15));
					if (debug) { System.out.println("Decoding Retired Priv 15: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_16: {
					this.retiredKMCert16 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 16: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_16: {
					this.retiredKMPrivKey16 = keyFromBytes(value, getKeyType(this.retiredKMCert16));
					if (debug) { System.out.println("Decoding Retired Priv 16: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_17: {
					this.retiredKMCert17 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 17: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_17: {
					this.retiredKMPrivKey17 = keyFromBytes(value, getKeyType(this.retiredKMCert17));
					if (debug) { System.out.println("Decoding Retired Priv 17: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_18: {
					this.retiredKMCert18 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 18: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_18: {
					this.retiredKMPrivKey18 = keyFromBytes(value, getKeyType(this.retiredKMCert18));
					if (debug) { System.out.println("Decoding Retired Priv 18: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_19: {
					this.retiredKMCert19 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 19: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_19: {
					this.retiredKMPrivKey19 = keyFromBytes(value, getKeyType(this.retiredKMCert19));
					if (debug) { System.out.println("Decoding Retired Priv 19: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMC_20: {
					this.retiredKMCert20 = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Retired KM Cert 20: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case KMK_20: {
					this.retiredKMPrivKey20 = keyFromBytes(value, getKeyType(this.retiredKMCert20));
					if (debug) { System.out.println("Decoding Retired Priv 20: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CII: {
					this.cardholderIrisImages = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Cardholder Iris Images: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case BITGT: {
					this.bioInfoTemplGrpTempl = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Bio Templates Group Template: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case SMC: {
					this.secMessagingCertSigner = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Sec Mess Cert Signer: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case SMK: {
					//SMK is Priv for CVC, not SMC, always ECC (P256 || P384)
					this.secMessagingPrivKey = keyFromBytes(value, KEY_ASYMMETRIC_ECC);
					if (debug) { System.out.println("Decoding SM Priv: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case PCRD: {
					this.pairingCodeReferenceData = new PIVDataTempl(value);
					if (debug) { System.out.println("Decoding Pairing Code Reference Data: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CPN: {
					this.cakPopNonce = value;
					if (debug) { System.out.println("Decoding CAK PoP Nonce: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				case CPS: {
					this.cakPopSig = value;
					if (debug) { System.out.println("Decoding CAK PoP Sig: " + DataUtil.byteArrayToString(value)); }
					break;
				}
				default: {
					//Should not get here
					break;
				}
			}
		}
	}

	/**
	 * Method keyFromBytes.
	 * @param bytes byte[]
	 * @param keyType int
	 * @return Key
	 */
	private Key keyFromBytes(byte[] bytes, int keyType) {
		Key _key = null;
		try {
			switch (keyType) {
			case KEY_SYMMETRIC_3DES: {
				_key = new SecretKeySpec(bytes, "3DES");
				break;
			}
			case KEY_SYMMETRIC_AES: {
				_key = new SecretKeySpec(bytes, "AES");
				break;
			}
			case KEY_ASYMMETRIC_RSA: {
				_key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
				break;
			}
			case KEY_ASYMMETRIC_ECC: {
				_key = KeyFactory.getInstance("ECC").generatePrivate(new PKCS8EncodedKeySpec(bytes));
				break;
			}
			case KEY_ASYMMETRIC_DSA: {
				_key = KeyFactory.getInstance("DSA").generatePrivate(new PKCS8EncodedKeySpec(bytes));
				break;
			}
			default: {
				//Should never reach this
				break;
			}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return _key;
	}

	/**
	 * Method getKeyType.
	 * @param key Key
	 * @return int
	 */
	private static int getKeyType(Key key) {
		int kType = -1;
		if (key.getAlgorithm().equals("3DES")) {
			kType = KEY_SYMMETRIC_3DES;
		} else if (key.getAlgorithm().equals("AES")) {
			kType = KEY_SYMMETRIC_AES;
		}
		return kType;
	}

	/**
	 * Method keyTypeFromBA.
	 * @param ba byte[]
	 * @return int
	 */
	private static int keyTypeFromBA(byte[] ba) {
		return ByteBuffer.wrap(ba).getInt();
	}
	
	/**
	 * Method keyTypeToBA.
	 * @param type int
	 * @return byte[]
	 */
	private static byte[] keyTypeToBA(int type) {
		return ByteBuffer.allocate(4).putInt(type).array();
	}	
	
	/**
	 * Method getKeyType.
	 * @param data PIVDataTempl
	 * @return int
	 */
	private static int getKeyType(PIVDataTempl data) {
		int kType = -1;
		PIVCertificate pCert = new PIVCertificate(data.getData());
		PublicKey pubKey = null;
		try {
			pubKey = pCert.getCertificate().getPublicKey();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (pubKey instanceof RSAPublicKey) {
			kType = KEY_ASYMMETRIC_RSA;
		} else if (pubKey instanceof ECPublicKey) {
			kType = KEY_ASYMMETRIC_ECC;
		} else if (pubKey instanceof DSAPublicKey) {
			kType = KEY_ASYMMETRIC_DSA;
		}
		return kType;
	}
	
	/**
	 * Method getATSHB.
	 * @return byte[]
	 */
	public byte[] getATSHB() {
		return this.aTSHistoricalBytes;
	}
	
	/**
	 * Method setATSHB.
	 * @param atshb byte[]
	 */
	public void setATSHB(byte[] atshb) {
		this.aTSHistoricalBytes = atshb;
	}
	
	/**
	 * Method getCPLC.
	 * @return byte[]
	 */
	public byte[] getCPLC() {
		return this.cardProdLifecycle;
	}
	
	/**
	 * Method setCPLC.
	 * @param cplc byte[]
	 */
	public void setCPLC(byte[] cplc) {
		this.cardProdLifecycle = cplc;
	}
	
	/**
	 * Method getCSN.
	 * @return byte[]
	 */
	public byte[] getCSN() {
		return this.cSNuID;
	}
	
	/**
	 * Method setCSN.
	 * @param csn byte[]
	 */
	public void setCSN(byte[] csn) {
		this.cSNuID = csn;
	}
	
	/**
	 * Method getPIVCardApplicationProperty.
	 * @return PIVDataTempl
	 */
	public PIVDataTempl getPIVCardApplicationProperty() {
		return this.applicationProperty;
	}
	
	/**
	 * Method setPIVCardApplicationProperty.
	 * @param pcap PIVDataTempl
	 */
	public void setPIVCardApplicationProperty(PIVDataTempl pcap) {
		this.applicationProperty = pcap;
	}
	
	/**
	 * Method getPIVCardHolderUniqueID.
	 * @return PIVDataTempl
	 */
	public PIVDataTempl getPIVCardHolderUniqueID() {
		return this.cardHolderUniqueId;
	}
	
	/**
	 * Method setPIVCardHolderUniqueID.
	 * @param chuid PIVDataTempl
	 */
	public void setPIVCardHolderUniqueID(PIVDataTempl chuid) {
		this.cardHolderUniqueId = chuid;
	}
	
	/**
	 * Method getPIVDiscoveryObject.
	 * @return PIVDataTempl
	 */
	public PIVDataTempl getPIVDiscoveryObject() {
		return this.discoveryObject;
	}
	
	/**
	 * Method setPIVDiscoveryObject.
	 * @param pdo PIVDataTempl
	 */
	public void setPIVDiscoveryObject(PIVDataTempl pdo) {
		this.discoveryObject = pdo;
	}
	
	/**
	 * Method getCardAuthCertificate.
	 * @return PIVDataTempl
	 */
	public PIVDataTempl getCardAuthCertificate() {
		return this.cardAuthCertificate;
	}
	
	/**
	 * Method setCardAuthCertificate.
	 * @param cardauthcert PIVDataTempl
	 */
	public void setCardAuthCertificate(PIVDataTempl cardauthcert) {
		this.cardAuthCertificate = cardauthcert;
	}
	
	/**
	
	 * @return the cardauthpriv */
	public Key getCardAuthPrivate() {
		return this.cardAuthPrivateKey;
	}

	/**
	 * @param cardauthpriv the cardauthpriv to set
	 */
	public void setCardAuthPrivate(Key cardauthpriv) {
		this.cardAuthPrivateKey = cardauthpriv;
	}

	/**
	
	 * @return the cardauthsym */
	public Key getCardAuthSymmetric() {
		return this.cardAuthSymKey;
	}

	/**
	 * @param cardauthsym the cardauthsym to set
	 */
	public void setCardAuthSymmetric(Key cardauthsym) {
		this.cardAuthSymKey = cardauthsym;
		this.cardAuthKeyType = keyTypeToBA(getKeyType(cardauthsym));
	}

	/**
	 * @return the pAdminKey
	 */
	public Key getpAdminKey() {
		return pAdminKey;
	}

	/**
	 * @param pAdminKey the pAdminKey to set
	 */
	public void setpAdminKey(Key pAdminKey) {
		this.pAdminKey = pAdminKey;
		this.pAdminKeyType = keyTypeToBA(getKeyType(pAdminKey));
	}

	/**
	 * @return the cardCapabilityCont
	 */
	public PIVDataTempl getCardCapabilityCont() {
		return cardCapabilityCont;
	}

	/**
	 * @param cardCapabilityCont the cardCapabilityCont to set
	 */
	public void setCardCapabilityCont(PIVDataTempl cardCapabilityCont) {
		this.cardCapabilityCont = cardCapabilityCont;
	}

	/**
	 * @return the pIVAuthCertificate
	 */
	public PIVDataTempl getpIVAuthCertificate() {
		return pIVAuthCertificate;
	}

	/**
	 * @param pIVAuthCertificate the pIVAuthCertificate to set
	 */
	public void setpIVAuthCertificate(PIVDataTempl pIVAuthCertificate) {
		this.pIVAuthCertificate = pIVAuthCertificate;
	}

	/**
	 * @return the pIVAuthPrivateKey
	 */
	public Key getpIVAuthPrivateKey() {
		return pIVAuthPrivateKey;
	}

	/**
	 * @param pIVAuthPrivateKey the pIVAuthPrivateKey to set
	 */
	public void setpIVAuthPrivateKey(Key pIVAuthPrivateKey) {
		this.pIVAuthPrivateKey = pIVAuthPrivateKey;
	}

	/**
	 * @return the cardholderFingerprints
	 */
	public PIVDataTempl getCardholderFingerprints() {
		return cardholderFingerprints;
	}

	/**
	 * @param cardholderFingerprints the cardholderFingerprints to set
	 */
	public void setCardholderFingerprints(PIVDataTempl cardholderFingerprints) {
		this.cardholderFingerprints = cardholderFingerprints;
	}

	/**
	 * @return the securityObject
	 */
	public PIVDataTempl getSecurityObject() {
		return securityObject;
	}

	/**
	 * @param securityObject the securityObject to set
	 */
	public void setSecurityObject(PIVDataTempl securityObject) {
		this.securityObject = securityObject;
	}

	/**
	 * @return the cardholderFacialImage
	 */
	public PIVDataTempl getCardholderFacialImage() {
		return cardholderFacialImage;
	}

	/**
	 * @param cardholderFacialImage the cardholderFacialImage to set
	 */
	public void setCardholderFacialImage(PIVDataTempl cardholderFacialImage) {
		this.cardholderFacialImage = cardholderFacialImage;
	}

	/**
	 * @return the digSigCertificate
	 */
	public PIVDataTempl getDigSigCertificate() {
		return digSigCertificate;
	}

	/**
	 * @param digSigCertificate the digSigCertificate to set
	 */
	public void setDigSigCertificate(PIVDataTempl digSigCertificate) {
		this.digSigCertificate = digSigCertificate;
	}

	/**
	 * @return the digSigPrivateKey
	 */
	public Key getDigSigPrivateKey() {
		return digSigPrivateKey;
	}

	/**
	 * @param digSigPrivateKey the digSigPrivateKey to set
	 */
	public void setDigSigPrivateKey(Key digSigPrivateKey) {
		this.digSigPrivateKey = digSigPrivateKey;
	}

	/**
	 * @return the keyMgmtCertificate
	 */
	public PIVDataTempl getKeyMgmtCertificate() {
		return keyMgmtCertificate;
	}

	/**
	 * @param keyMgmtCertificate the keyMgmtCertificate to set
	 */
	public void setKeyMgmtCertificate(PIVDataTempl keyMgmtCertificate) {
		this.keyMgmtCertificate = keyMgmtCertificate;
	}

	/**
	 * @return the keyMgmtPrivateKey
	 */
	public Key getKeyMgmtPrivateKey() {
		return keyMgmtPrivateKey;
	}

	/**
	 * @param keyMgmtPrivateKey the keyMgmtPrivateKey to set
	 */
	public void setKeyMgmtPrivateKey(Key keyMgmtPrivateKey) {
		this.keyMgmtPrivateKey = keyMgmtPrivateKey;
	}

	/**
	 * @return the printedInformation
	 */
	public PIVDataTempl getPrintedInformation() {
		return printedInformation;
	}

	/**
	 * @param printedInformation the printedInformation to set
	 */
	public void setPrintedInformation(PIVDataTempl printedInformation) {
		this.printedInformation = printedInformation;
	}

	/**
	 * @return the keyHistoryObject
	 */
	public PIVDataTempl getKeyHistoryObject() {
		return keyHistoryObject;
	}

	/**
	 * @param keyHistoryObject the keyHistoryObject to set
	 */
	public void setKeyHistoryObject(PIVDataTempl keyHistoryObject) {
		this.keyHistoryObject = keyHistoryObject;
	}

	/**
	 * @return the retiredKMCert01
	 */
	public PIVDataTempl getRetiredKMCert01() {
		return retiredKMCert01;
	}

	/**
	 * @param retiredKMCert01 the retiredKMCert01 to set
	 */
	public void setRetiredKMCert01(PIVDataTempl retiredKMCert01) {
		this.retiredKMCert01 = retiredKMCert01;
	}

	/**
	 * @return the retiredKMPrivKey01
	 */
	public Key getRetiredKMPrivKey01() {
		return retiredKMPrivKey01;
	}

	/**
	 * @param retiredKMPrivKey01 the retiredKMPrivKey01 to set
	 */
	public void setRetiredKMPrivKey01(Key retiredKMPrivKey01) {
		this.retiredKMPrivKey01 = retiredKMPrivKey01;
	}

	/**
	 * @return the retiredKMCert02
	 */
	public PIVDataTempl getRetiredKMCert02() {
		return retiredKMCert02;
	}

	/**
	 * @param retiredKMCert02 the retiredKMCert02 to set
	 */
	public void setRetiredKMCert02(PIVDataTempl retiredKMCert02) {
		this.retiredKMCert02 = retiredKMCert02;
	}

	/**
	 * @return the retiredKMPrivKey02
	 */
	public Key getRetiredKMPrivKey02() {
		return retiredKMPrivKey02;
	}

	/**
	 * @param retiredKMPrivKey02 the retiredKMPrivKey02 to set
	 */
	public void setRetiredKMPrivKey02(Key retiredKMPrivKey02) {
		this.retiredKMPrivKey02 = retiredKMPrivKey02;
	}

	/**
	 * @return the retiredKMCert03
	 */
	public PIVDataTempl getRetiredKMCert03() {
		return retiredKMCert03;
	}

	/**
	 * @param retiredKMCert03 the retiredKMCert03 to set
	 */
	public void setRetiredKMCert03(PIVDataTempl retiredKMCert03) {
		this.retiredKMCert03 = retiredKMCert03;
	}

	/**
	 * @return the retiredKMPrivKey03
	 */
	public Key getRetiredKMPrivKey03() {
		return retiredKMPrivKey03;
	}

	/**
	 * @param retiredKMPrivKey03 the retiredKMPrivKey03 to set
	 */
	public void setRetiredKMPrivKey03(Key retiredKMPrivKey03) {
		this.retiredKMPrivKey03 = retiredKMPrivKey03;
	}

	/**
	 * @return the retiredKMCert04
	 */
	public PIVDataTempl getRetiredKMCert04() {
		return retiredKMCert04;
	}

	/**
	 * @param retiredKMCert04 the retiredKMCert04 to set
	 */
	public void setRetiredKMCert04(PIVDataTempl retiredKMCert04) {
		this.retiredKMCert04 = retiredKMCert04;
	}

	/**
	 * @return the retiredKMPrivKey04
	 */
	public Key getRetiredKMPrivKey04() {
		return retiredKMPrivKey04;
	}

	/**
	 * @param retiredKMPrivKey04 the retiredKMPrivKey04 to set
	 */
	public void setRetiredKMPrivKey04(Key retiredKMPrivKey04) {
		this.retiredKMPrivKey04 = retiredKMPrivKey04;
	}

	/**
	 * @return the retiredKMCert05
	 */
	public PIVDataTempl getRetiredKMCert05() {
		return retiredKMCert05;
	}

	/**
	 * @param retiredKMCert05 the retiredKMCert05 to set
	 */
	public void setRetiredKMCert05(PIVDataTempl retiredKMCert05) {
		this.retiredKMCert05 = retiredKMCert05;
	}

	/**
	 * @return the retiredKMPrivKey05
	 */
	public Key getRetiredKMPrivKey05() {
		return retiredKMPrivKey05;
	}

	/**
	 * @param retiredKMPrivKey05 the retiredKMPrivKey05 to set
	 */
	public void setRetiredKMPrivKey05(Key retiredKMPrivKey05) {
		this.retiredKMPrivKey05 = retiredKMPrivKey05;
	}

	/**
	 * @return the retiredKMCert06
	 */
	public PIVDataTempl getRetiredKMCert06() {
		return retiredKMCert06;
	}

	/**
	 * @param retiredKMCert06 the retiredKMCert06 to set
	 */
	public void setRetiredKMCert06(PIVDataTempl retiredKMCert06) {
		this.retiredKMCert06 = retiredKMCert06;
	}

	/**
	 * @return the retiredKMPrivKey06
	 */
	public Key getRetiredKMPrivKey06() {
		return retiredKMPrivKey06;
	}

	/**
	 * @param retiredKMPrivKey06 the retiredKMPrivKey06 to set
	 */
	public void setRetiredKMPrivKey06(Key retiredKMPrivKey06) {
		this.retiredKMPrivKey06 = retiredKMPrivKey06;
	}

	/**
	 * @return the retiredKMCert07
	 */
	public PIVDataTempl getRetiredKMCert07() {
		return retiredKMCert07;
	}

	/**
	 * @param retiredKMCert07 the retiredKMCert07 to set
	 */
	public void setRetiredKMCert07(PIVDataTempl retiredKMCert07) {
		this.retiredKMCert07 = retiredKMCert07;
	}

	/**
	 * @return the retiredKMPrivKey07
	 */
	public Key getRetiredKMPrivKey07() {
		return retiredKMPrivKey07;
	}

	/**
	 * @param retiredKMPrivKey07 the retiredKMPrivKey07 to set
	 */
	public void setRetiredKMPrivKey07(Key retiredKMPrivKey07) {
		this.retiredKMPrivKey07 = retiredKMPrivKey07;
	}

	/**
	 * @return the retiredKMCert08
	 */
	public PIVDataTempl getRetiredKMCert08() {
		return retiredKMCert08;
	}

	/**
	 * @param retiredKMCert08 the retiredKMCert08 to set
	 */
	public void setRetiredKMCert08(PIVDataTempl retiredKMCert08) {
		this.retiredKMCert08 = retiredKMCert08;
	}

	/**
	 * @return the retiredKMPrivKey08
	 */
	public Key getRetiredKMPrivKey08() {
		return retiredKMPrivKey08;
	}

	/**
	 * @param retiredKMPrivKey08 the retiredKMPrivKey08 to set
	 */
	public void setRetiredKMPrivKey08(Key retiredKMPrivKey08) {
		this.retiredKMPrivKey08 = retiredKMPrivKey08;
	}

	/**
	 * @return the retiredKMCert09
	 */
	public PIVDataTempl getRetiredKMCert09() {
		return retiredKMCert09;
	}

	/**
	 * @param retiredKMCert09 the retiredKMCert09 to set
	 */
	public void setRetiredKMCert09(PIVDataTempl retiredKMCert09) {
		this.retiredKMCert09 = retiredKMCert09;
	}

	/**
	 * @return the retiredKMPrivKey09
	 */
	public Key getRetiredKMPrivKey09() {
		return retiredKMPrivKey09;
	}

	/**
	 * @param retiredKMPrivKey09 the retiredKMPrivKey09 to set
	 */
	public void setRetiredKMPrivKey09(Key retiredKMPrivKey09) {
		this.retiredKMPrivKey09 = retiredKMPrivKey09;
	}

	/**
	 * @return the retiredKMCert10
	 */
	public PIVDataTempl getRetiredKMCert10() {
		return retiredKMCert10;
	}

	/**
	 * @param retiredKMCert10 the retiredKMCert10 to set
	 */
	public void setRetiredKMCert10(PIVDataTempl retiredKMCert10) {
		this.retiredKMCert10 = retiredKMCert10;
	}

	/**
	 * @return the retiredKMPrivKey10
	 */
	public Key getRetiredKMPrivKey10() {
		return retiredKMPrivKey10;
	}

	/**
	 * @param retiredKMPrivKey10 the retiredKMPrivKey10 to set
	 */
	public void setRetiredKMPrivKey10(Key retiredKMPrivKey10) {
		this.retiredKMPrivKey10 = retiredKMPrivKey10;
	}

	/**
	 * @return the retiredKMCert11
	 */
	public PIVDataTempl getRetiredKMCert11() {
		return retiredKMCert11;
	}

	/**
	 * @param retiredKMCert11 the retiredKMCert11 to set
	 */
	public void setRetiredKMCert11(PIVDataTempl retiredKMCert11) {
		this.retiredKMCert11 = retiredKMCert11;
	}

	/**
	 * @return the retiredKMPrivKey11
	 */
	public Key getRetiredKMPrivKey11() {
		return retiredKMPrivKey11;
	}

	/**
	 * @param retiredKMPrivKey11 the retiredKMPrivKey11 to set
	 */
	public void setRetiredKMPrivKey11(Key retiredKMPrivKey11) {
		this.retiredKMPrivKey11 = retiredKMPrivKey11;
	}

	/**
	 * @return the retiredKMCert12
	 */
	public PIVDataTempl getRetiredKMCert12() {
		return retiredKMCert12;
	}

	/**
	 * @param retiredKMCert12 the retiredKMCert12 to set
	 */
	public void setRetiredKMCert12(PIVDataTempl retiredKMCert12) {
		this.retiredKMCert12 = retiredKMCert12;
	}

	/**
	 * @return the retiredKMPrivKey12
	 */
	public Key getRetiredKMPrivKey12() {
		return retiredKMPrivKey12;
	}

	/**
	 * @param retiredKMPrivKey12 the retiredKMPrivKey12 to set
	 */
	public void setRetiredKMPrivKey12(Key retiredKMPrivKey12) {
		this.retiredKMPrivKey12 = retiredKMPrivKey12;
	}

	/**
	 * @return the retiredKMCert13
	 */
	public PIVDataTempl getRetiredKMCert13() {
		return retiredKMCert13;
	}

	/**
	 * @param retiredKMCert13 the retiredKMCert13 to set
	 */
	public void setRetiredKMCert13(PIVDataTempl retiredKMCert13) {
		this.retiredKMCert13 = retiredKMCert13;
	}

	/**
	 * @return the retiredKMPrivKey13
	 */
	public Key getRetiredKMPrivKey13() {
		return retiredKMPrivKey13;
	}

	/**
	 * @param retiredKMPrivKey13 the retiredKMPrivKey13 to set
	 */
	public void setRetiredKMPrivKey13(Key retiredKMPrivKey13) {
		this.retiredKMPrivKey13 = retiredKMPrivKey13;
	}

	/**
	 * @return the retiredKMCert14
	 */
	public PIVDataTempl getRetiredKMCert14() {
		return retiredKMCert14;
	}

	/**
	 * @param retiredKMCert14 the retiredKMCert14 to set
	 */
	public void setRetiredKMCert14(PIVDataTempl retiredKMCert14) {
		this.retiredKMCert14 = retiredKMCert14;
	}

	/**
	 * @return the retiredKMPrivKey14
	 */
	public Key getRetiredKMPrivKey14() {
		return retiredKMPrivKey14;
	}

	/**
	 * @param retiredKMPrivKey14 the retiredKMPrivKey14 to set
	 */
	public void setRetiredKMPrivKey14(Key retiredKMPrivKey14) {
		this.retiredKMPrivKey14 = retiredKMPrivKey14;
	}

	/**
	 * @return the retiredKMCert15
	 */
	public PIVDataTempl getRetiredKMCert15() {
		return retiredKMCert15;
	}

	/**
	 * @param retiredKMCert15 the retiredKMCert15 to set
	 */
	public void setRetiredKMCert15(PIVDataTempl retiredKMCert15) {
		this.retiredKMCert15 = retiredKMCert15;
	}

	/**
	 * @return the retiredKMPrivKey15
	 */
	public Key getRetiredKMPrivKey15() {
		return retiredKMPrivKey15;
	}

	/**
	 * @param retiredKMPrivKey15 the retiredKMPrivKey15 to set
	 */
	public void setRetiredKMPrivKey15(Key retiredKMPrivKey15) {
		this.retiredKMPrivKey15 = retiredKMPrivKey15;
	}

	/**
	 * @return the retiredKMCert16
	 */
	public PIVDataTempl getRetiredKMCert16() {
		return retiredKMCert16;
	}

	/**
	 * @param retiredKMCert16 the retiredKMCert16 to set
	 */
	public void setRetiredKMCert16(PIVDataTempl retiredKMCert16) {
		this.retiredKMCert16 = retiredKMCert16;
	}

	/**
	 * @return the retiredKMPrivKey16
	 */
	public Key getRetiredKMPrivKey16() {
		return retiredKMPrivKey16;
	}

	/**
	 * @param retiredKMPrivKey16 the retiredKMPrivKey16 to set
	 */
	public void setRetiredKMPrivKey16(Key retiredKMPrivKey16) {
		this.retiredKMPrivKey16 = retiredKMPrivKey16;
	}

	/**
	 * @return the retiredKMCert17
	 */
	public PIVDataTempl getRetiredKMCert17() {
		return retiredKMCert17;
	}

	/**
	 * @param retiredKMCert17 the retiredKMCert17 to set
	 */
	public void setRetiredKMCert17(PIVDataTempl retiredKMCert17) {
		this.retiredKMCert17 = retiredKMCert17;
	}

	/**
	 * @return the retiredKMPrivKey17
	 */
	public Key getRetiredKMPrivKey17() {
		return retiredKMPrivKey17;
	}

	/**
	 * @param retiredKMPrivKey17 the retiredKMPrivKey17 to set
	 */
	public void setRetiredKMPrivKey17(Key retiredKMPrivKey17) {
		this.retiredKMPrivKey17 = retiredKMPrivKey17;
	}

	/**
	 * @return the retiredKMCert18
	 */
	public PIVDataTempl getRetiredKMCert18() {
		return retiredKMCert18;
	}

	/**
	 * @param retiredKMCert18 the retiredKMCert18 to set
	 */
	public void setRetiredKMCert18(PIVDataTempl retiredKMCert18) {
		this.retiredKMCert18 = retiredKMCert18;
	}

	/**
	 * @return the retiredKMPrivKey18
	 */
	public Key getRetiredKMPrivKey18() {
		return retiredKMPrivKey18;
	}

	/**
	 * @param retiredKMPrivKey18 the retiredKMPrivKey18 to set
	 */
	public void setRetiredKMPrivKey18(Key retiredKMPrivKey18) {
		this.retiredKMPrivKey18 = retiredKMPrivKey18;
	}

	/**
	 * @return the retiredKMCert19
	 */
	public PIVDataTempl getRetiredKMCert19() {
		return retiredKMCert19;
	}

	/**
	 * @param retiredKMCert19 the retiredKMCert19 to set
	 */
	public void setRetiredKMCert19(PIVDataTempl retiredKMCert19) {
		this.retiredKMCert19 = retiredKMCert19;
	}

	/**
	 * @return the retiredKMPrivKey19
	 */
	public Key getRetiredKMPrivKey19() {
		return retiredKMPrivKey19;
	}

	/**
	 * @param retiredKMPrivKey19 the retiredKMPrivKey19 to set
	 */
	public void setRetiredKMPrivKey19(Key retiredKMPrivKey19) {
		this.retiredKMPrivKey19 = retiredKMPrivKey19;
	}

	/**
	 * @return the retiredKMCert20
	 */
	public PIVDataTempl getRetiredKMCert20() {
		return retiredKMCert20;
	}

	/**
	 * @param retiredKMCert20 the retiredKMCert20 to set
	 */
	public void setRetiredKMCert20(PIVDataTempl retiredKMCert20) {
		this.retiredKMCert20 = retiredKMCert20;
	}

	/**
	 * @return the retiredKMPrivKey20
	 */
	public Key getRetiredKMPrivKey20() {
		return retiredKMPrivKey20;
	}

	/**
	 * @param retiredKMPrivKey20 the retiredKMPrivKey20 to set
	 */
	public void setRetiredKMPrivKey20(Key retiredKMPrivKey20) {
		this.retiredKMPrivKey20 = retiredKMPrivKey20;
	}

	/**
	 * @return the cardholderIrisImages
	 */
	public PIVDataTempl getCardholderIrisImages() {
		return cardholderIrisImages;
	}

	/**
	 * @param cardholderIrisImages the cardholderIrisImages to set
	 */
	public void setCardholderIrisImages(PIVDataTempl cardholderIrisImages) {
		this.cardholderIrisImages = cardholderIrisImages;
	}

	/**
	 * @return the bioInfoTemplGrpTempl
	 */
	public PIVDataTempl getBioInfoTemplGrpTempl() {
		return bioInfoTemplGrpTempl;
	}

	/**
	 * @param bioInfoTemplGrpTempl the bioInfoTemplGrpTempl to set
	 */
	public void setBioInfoTemplGrpTempl(PIVDataTempl bioInfoTemplGrpTempl) {
		this.bioInfoTemplGrpTempl = bioInfoTemplGrpTempl;
	}

	/**
	 * @return the secMessagingCertSigner
	 */
	public PIVDataTempl getSecMessagingCertSigner() {
		return secMessagingCertSigner;
	}

	/**
	 * @param secMessagingCertSigner the secMessagingCertSigner to set
	 */
	public void setSecMessagingCertSigner(PIVDataTempl secMessagingCertSigner) {
		this.secMessagingCertSigner = secMessagingCertSigner;
	}

	/**
	 * @return the secMessagingPrivKey
	 */
	public Key getSecMessagingPrivKey() {
		return secMessagingPrivKey;
	}

	/**
	 * @param secMessagingPrivKey the secMessagingPrivKey to set
	 */
	public void setSecMessagingPrivKey(Key secMessagingPrivKey) {
		this.secMessagingPrivKey = secMessagingPrivKey;
	}

	/**
	 * @return the pairingCodeReferenceData
	 */
	public PIVDataTempl getPairingCodeReferenceData() {
		return pairingCodeReferenceData;
	}

	/**
	 * @param pairingCodeReferenceData the pairingCodeReferenceData to set
	 */
	public void setPairingCodeReferenceData(PIVDataTempl pairingCodeReferenceData) {
		this.pairingCodeReferenceData = pairingCodeReferenceData;
	}

	/**
	 * @return the cakPopNonce
	 */
	public byte[] getCAKPoPNonce() {
		return cakPopNonce;
	}

	/**
	 * @param cakPopNonce the cakPopNonce to set
	 */
	public void setCAKPoPNonce(byte[] cakPopNonce) {
		this.cakPopNonce = cakPopNonce;
	}

	/**
	 * @return the cakPopSig
	 */
	public byte[] getCAKPoPSig() {
		return cakPopSig;
	}

	/**
	 * @param cakPopSig the cakPopSig to set
	 */
	public void setCAKPoPSig(byte[] cakPopSig) {
		this.cakPopSig = cakPopSig;
	}

}
