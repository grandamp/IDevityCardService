package com.idevity.card.read;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import org.keysupport.asn1.ASN1Exception;
import org.keysupport.asn1.ASN1Factory;
import org.keysupport.asn1.ASN1Object;
import org.keysupport.asn1.BOOLEAN;
import org.keysupport.asn1.CON_SPEC;
import org.keysupport.asn1.INTEGER;
import org.keysupport.asn1.SEQUENCE;
import org.keysupport.encoding.BERTLVFactory;
import org.keysupport.encoding.TLV;
import org.keysupport.encoding.TLVEncodingException;
import org.keysupport.encoding.der.ObjectIdentifier;
import org.keysupport.encoding.der.structures.AlgorithmIdentifier;
import org.keysupport.keystore.CipherEngine;
import org.keysupport.keystore.DigestEngine;
import org.keysupport.nist80073.cardedge.PIVDataTempl;
import org.keysupport.nist80073.datamodel.PIVCertificate;
import org.keysupport.util.DataUtil;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.NfcAdapter.ReaderCallback;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.preference.PreferenceManager;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.TextView;

import com.idevity.card.data.CardData80073;
import com.idevity.card.service.EmulationLogActivity;
import com.idevity.card.service.R;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: Read80073.java 307 2014-02-03 00:56:22Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 307 $
 * 
 *          Changed: $LastChangedDate: 2013-11-07 00:31:22 -0500 (Thu, 07 Nov
 *          2013) $
 *****************************************************************************/
public class CloneKeys extends Activity implements OnClickListener {

	/**
	 * Field TAG.
	 */
	private static final String TAG = CloneKeys.class.getSimpleName();

	// open global variables
	/**
	 * Field g.
	 */
	Globals g = Globals.getInstance();

	/**
	 * Field instruction.
	 */
	private TextView instruction;
	/**
	 * Field launchButton.
	 */
	private Button launchButton;

	/**
	 * Field sharedPref.
	 */
	private SharedPreferences sharedPref;

	/**
	 * Field carddata.
	 */
	private CardData80073 carddata;
	/**
	 * Field debug.
	 */
	private boolean debug = false;
	/**
	 * Field last_touch.
	 */

	/**
	 * Method onCreate.
	 * 
	 * @param savedInstanceState
	 *            Bundle
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		sharedPref = PreferenceManager.getDefaultSharedPreferences(this);
		debug = sharedPref.getBoolean(g.getShowDebug(), false);

		/*
		 * We will take over the NFC Interface while in the foreground so there
		 * is no additional read attempt.
		 * 
		 * If on KitKat, we will set a filter and ignore any callbacks.
		 */
		/****************** Initialize NFC ******************/
		if (debug) {
			Log.d(TAG, "Getting Adaptor...");
		}
		NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
		/*
		 * Platform version specific handling: KitKat
		 */
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN_MR2) {
			if (debug) {
				Log.d(TAG, "Setting Adaptor up for KitKat");
			}
			ReaderCallback listener = new ReaderCallback() {
				public void onTagDiscovered(Tag tag) {
					/*
					 * Discard the tags here
					 */
					tag = null;
				}
			};
			int flags = NfcAdapter.FLAG_READER_NFC_A
					| NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK
					| NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS;
			adapter.enableReaderMode(this, listener, flags, null);
		}

		/****************** Manage the UI ******************/
		setContentView(R.layout.activity_clone_keys);
		
		instruction = (TextView) findViewById(R.id.instructions3);
		launchButton = (Button) findViewById(R.id.button1);

		instruction.setVisibility(View.INVISIBLE);
		launchButton.setVisibility(View.INVISIBLE);

		launchButton.setOnClickListener(new View.OnClickListener() {
			public void onClick(View v) {
				processData();
			}
		});


		/****************** Clone the keys ******************/
		/*
		 * Inspect the intent that possibly launched us and take action
		 */
		/*
		 * Check and see if an intent was used to launch us. If the intent has
		 * data, obtain it, otherwise, send them back.
		 */
		try {
			if (getIntent() != null) {
				Intent intent = getIntent();
				if (debug) {
					Log.d(TAG, "Intent hasExtras: "
						+ intent.getExtras().toString());
				}
				byte[] _data = getIntent().getExtras().getByteArray(
						g.getCardData());
				carddata = new CardData80073(_data);
				if (debug) {
					Log.d(TAG, "Using new card data");
				}
			} else if (g.getCard() != null) {
					byte[] _data = g.getCard();
					carddata = new CardData80073(_data);
					Log.e(TAG, "Using saved card data");
			} else {
				Intent returnuser = new Intent(this, Read80073.class);
				startActivity(returnuser);
				Log.e(TAG,
						"No card data found; returning user to read a new card.");
			}	
		} catch (Throwable e) {
			Log.e(TAG, "Error: " + e.getMessage());
			if (debug) {
				e.printStackTrace();
			}
		}
					
		if (debug) {
			Log.d(TAG, "Cloning Keys...");
		}

		/****************** Launch UI Updating Thread ******************/
		Thread thread = new Thread() {
			@Override
			public void run() {
				try {
					runOnUiThread(new Runnable() {
						@Override
						public void run() {
							/*
							 * Gen a keyPair and replace the public key in the Card
							 * Auth Cert with the new public key.
							 * 
							 * Include our private key in the carddata.
							 */
							try {
								carddata = cloneCardAuthCertificate(carddata);
							} catch (CertificateException e) {
								e.printStackTrace();
							} catch (IOException e) {
								e.printStackTrace();
							} catch (InvalidKeyException e) {
								e.printStackTrace();
							} catch (NoSuchAlgorithmException e) {
								e.printStackTrace();
							} catch (NoSuchProviderException e) {
								e.printStackTrace();
							} catch (SignatureException e) {
								e.printStackTrace();
							} catch (ASN1Exception e) {
								e.printStackTrace();
							} catch (TLVEncodingException e) {
								e.printStackTrace();
							}
							instruction.setVisibility(View.VISIBLE);
							launchButton.setVisibility(View.VISIBLE);
						}
					});
				} catch (Throwable e) {
					if (debug) {
						Log.d(TAG, "Error in UI Thread: " + e.getMessage());
					}
				}
			}
		};
		thread.start();

		if (debug) {
			Log.d(TAG, "Finished cloning Keys...");
		}

	}

	/**
	 * Method processData.
	 * 
	 * Post processing and send the data to the next activity.
	 */
	private void processData() {
		/*
		 * Call EmulationLogActivity
		 */
		Intent intent = new Intent(this, EmulationLogActivity.class);
		intent.putExtra(g.getCardData(), carddata.toByteArray());
		startActivity(intent);
	}

	/**
	 * Method onResume.
	 */
	@Override
	public void onResume() {
		if (debug) {
			Log.d(TAG, "onResume()");
		}
		super.onResume();
	}

	/**
	 * Method onPause.
	 */
	@Override
	public void onPause() {
		if (debug) {
			Log.d(TAG, "onPause()");
		}
		super.onPause();
	}

	/**
	 * Method onDestroy.
	 */
	@Override
	public void onDestroy() {
		if (debug) {
			Log.d(TAG, "onDestroy()");
		}
		super.onDestroy();
	}

	/**
	 * Method onCreateOptionsMenu.
	 * 
	 * @param menu
	 *            Menu
	 * @return boolean
	 */
	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		/*
		 * Inflate the menu; this adds items to the action bar if it is present.
		 */
		getMenuInflater().inflate(R.menu.reading_progress, menu);
		return true;
	}

	/**
	 * Method onOptionsItemSelected.
	 * 
	 * @param item
	 *            MenuItem
	 * @return boolean
	 */
	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		/*
		 * Handle item selection
		 */
		switch (item.getItemId()) {
		case R.id.action_about:
			Intent callinfo = new Intent(this, IdevityInfo.class);
			startActivity(callinfo);
			return true;
		case R.id.action_settings:
			Intent callsettings = new Intent(this, SettingsActivity.class);
			startActivity(callsettings);
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}
	}

	/*
	 * Clones the cert contents
	 * Generates new keys
	 * Replaces the SKI & AKI & SubjectPublicKeyInfo
	 */
	public CardData80073 cloneCardAuthCertificate(CardData80073 carddata) throws CertificateException, IOException, NoSuchAlgorithmException, ASN1Exception, TLVEncodingException, InvalidKeyException, NoSuchProviderException, SignatureException {

		PIVDataTempl cac = carddata.getCardAuthCertificate();
		PIVCertificate cacPCert = null;
		X509Certificate target = null;
		
		if (cac == null) {
			return carddata;
		} else {
			cacPCert = new PIVCertificate(cac.getData());
			target = cacPCert.getCertificate();
		}
		// Get a handle on our keystore, our private signing key, and public
		// certificate
		PrivateKey prvSign = null;

		// Prep for new cert and private key
		X509Certificate newCertificate = null;
		PrivateKey nPrivKey = null;
		// Get the TBS Certificate
		byte[] toBeSigned = target.getTBSCertificate();
		// Get the current key
		PublicKey tPub = target.getPublicKey();
		// Determine key type
		String tPubAlg = tPub.getAlgorithm();
		System.out.println("Key Type: " + tPubAlg);
		// Determine the signing algorithm OID
		String tSigAlgOID = target.getSigAlgOID();
		System.out.println("Signature Algorithm: " + tSigAlgOID);
		// Get the key length, and generate a new keypair based on the algorithm
		// and length
		if (tPubAlg.equalsIgnoreCase("RSA")) {
			RSAPublicKey rsatPub = (RSAPublicKey) tPub;
			// Determine key size
			int tPubLen = rsatPub.getModulus().toByteArray().length;
			// Key size may be one byte bigger than key length to to a prepended
			// 0x00 pad. Likely due to the use of BigInteger
			if (tPubLen >= 128 && tPubLen <= 256) {
				tPubLen = 1024;
			}
			if (tPubLen >= 256) {
				tPubLen = 2048;
			}
			System.out.println("Key Size: " + tPubLen);

			KeyPairGenerator keygen = KeyPairGenerator.getInstance(tPubAlg);
			keygen.initialize(tPubLen);
			KeyPair nKP = keygen.generateKeyPair();
			PublicKey nPubKey = nKP.getPublic();
			nPrivKey = nKP.getPrivate();
			prvSign = nPrivKey;

			// Lets print the data we have generated to far to see where we
			// are...
			// Print the TBS Cert
			System.out.println("ToBeSigned:");
			System.out.println(DataUtil.byteArrayToString(toBeSigned));
			// Print the new Pub Key
			System.out.println("Pub:");
			System.out.println(DataUtil.byteArrayToString(nPubKey
					.getEncoded()));
			// Print the new Priv Key
			System.out.println("Priv:");
			System.out.println(DataUtil.byteArrayToString(nPrivKey
					.getEncoded()));

			RSAPublicKey rpub = (RSAPublicKey) nPubKey;
			/*
			 * Assuming an RSA Public Key on this one, with 0 un-used bits...
			 * Ugly way to do this since we can't get the SubjectPublicKey
			 * encoding through Java.
			 */
			SEQUENCE rpubkey = new SEQUENCE();
			INTEGER mod = new INTEGER(rpub.getModulus());
			INTEGER pe = new INTEGER(rpub.getPublicExponent());
			rpubkey.addComponent(mod);
			rpubkey.addComponent(pe);
			byte[] newSKIVal = DigestEngine.sHA1Sum(rpubkey.getBytes());
			System.out.println("New SKI:");
			System.out.println(DataUtil.byteArrayToString(newSKIVal));
			/*
			 * Replace the subjectPublicKeyInfo & SKI in the tbsCertificate with
			 * the one for our key
			 */
			ASN1Object caKeyID = null;

			SEQUENCE tbs = new SEQUENCE();
			Enumeration<ASN1Object> en = ASN1Factory
					.decodeASN1Object(toBeSigned);
			Enumeration<ASN1Object> en2 = ASN1Factory.decodeASN1Object(en
					.nextElement().getValue());
			int seq_count = 0;
			while (en2.hasMoreElements()) {
				ASN1Object cAobj = en2.nextElement();
				if (cAobj.getTag().equals(new org.keysupport.encoding.Tag(new byte[] { (byte) 0x30 }))) {
					if (seq_count == 4) {
						// If subjectPublicKeyInfo, replace with our new one
						tbs.addComponent(new ASN1Object(nPubKey.getEncoded()));
					} else {
						tbs.addComponent(cAobj);
						seq_count++;
					}
				} else if (cAobj.getTag().equals(
						new org.keysupport.encoding.Tag(new byte[] { (byte) 0xA3 }))) {
					// Replace SKI and append to tbs
					tbs.addComponent(replaceSkidandAkid(cAobj, newSKIVal,
							caKeyID));
				} else {
					tbs.addComponent(cAobj);
				}
			}
			System.out.println("Orig tbsCertificate:");
			System.out.println(DataUtil.byteArrayToString(toBeSigned));
			System.out.println("New tbsCertificate:");
			System.out.println(DataUtil.byteArrayToString(tbs.getBytes()));
			/*
			 * Sign the new certificate
			 */
			// Create the Certificate SEQ
			SEQUENCE new_cert = new SEQUENCE();
			// Append the TBSCertificate
			new_cert.addComponent(tbs);
			// Append the AlgorithmIdentifier
			new_cert.addComponent(new AlgorithmIdentifier(new ObjectIdentifier(
					target.getSigAlgOID()), null).getASN1Object());
			// Generate the signature
			Signature signature = Signature.getInstance(CipherEngine
					.getSigningAlgorithm(new ObjectIdentifier(target
							.getSigAlgOID())));
			signature.initSign(prvSign);
			signature.update(tbs.getBytes());
			byte[] sigval = signature.sign();
			System.out.println("New Signature:");
			System.out.println(DataUtil.byteArrayToString(sigval));

			// Append the Signature
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			// Add Padding Bits (again, RSA)
			baos.write((byte) 0x00);
			baos.write(sigval);
			new_cert.addComponent(ASN1Factory.encodeASN1Object(new org.keysupport.encoding.Tag(
					org.keysupport.encoding.Tag.BITSTRING), baos.toByteArray()));

			ByteArrayInputStream nbais = new ByteArrayInputStream(
					new_cert.getBytes());
			CertificateFactory cf = CertificateFactory.getInstance("X509");
			newCertificate = (X509Certificate) cf.generateCertificate(nbais);
			System.out.println("New Certificate:");
			System.out.println(newCertificate.toString());
			PublicKey caKey = null;
			caKey = newCertificate.getPublicKey();
			newCertificate.verify(caKey);
			
			PIVCertificate nCAC = new PIVCertificate(newCertificate.getEncoded(), null);
			TLV _data = BERTLVFactory.encodeTLV(new org.keysupport.encoding.Tag(org.keysupport.encoding.Tag.PIV_DATA), nCAC.getEncoded());
			PIVDataTempl nCac = new PIVDataTempl(_data.getBytes());
			carddata.setCardAuthCertificate(nCac);
			carddata.setCardAuthPrivate(nPrivKey);
		} else {
			// do nothing for now till we write code to support ECC
			// No need to support DSA
		}
		return carddata;
	}
	
	public final static ObjectIdentifier subjectKeyIdentifier = new ObjectIdentifier(
			"2.5.29.14");
	public final static ObjectIdentifier authorityKeyIdentifier = new ObjectIdentifier(
			"2.5.29.35");

	private static ASN1Object replaceSkidandAkid(ASN1Object extensions,
			byte[] skival, ASN1Object keyId) throws TLVEncodingException,
			ASN1Exception {
		Enumeration<ASN1Object> en = ASN1Factory.decodeASN1Object(extensions
				.getValue());
		Enumeration<ASN1Object> en2 = ASN1Factory.decodeASN1Object(en
				.nextElement().getValue());
		SEQUENCE extns = new SEQUENCE();
		while (en2.hasMoreElements()) {
			ASN1Object cAobj = en2.nextElement();
			Enumeration<ASN1Object> en3 = ASN1Factory.decodeASN1Object(cAobj
					.getValue());
			ObjectIdentifier curExtnId = new ObjectIdentifier(en3.nextElement()
					.getValue());
			if (curExtnId.equals(subjectKeyIdentifier)) {
				SEQUENCE ski = extensionBuilder(subjectKeyIdentifier, false,
						ASN1Factory.encodeASN1Object(new org.keysupport.encoding.Tag(org.keysupport.encoding.Tag.OCTETSTRING),
								skival));
				extns.addComponent(ski);
			} else if (curExtnId.equals(authorityKeyIdentifier)
					&& keyId != null) {
				CON_SPEC akival_keyId = new CON_SPEC(0, true, keyId.getValue());
				SEQUENCE akival = new SEQUENCE();
				akival.addComponent(akival_keyId);
				extns.addComponent(extensionBuilder(authorityKeyIdentifier,
						false, akival));
			} else {
				extns.addComponent(cAobj);
			}
		}
		CON_SPEC cextns = new CON_SPEC(3);
		cextns.addComponent(extns);
		return cextns;
	}

	private static SEQUENCE extensionBuilder(ObjectIdentifier extnId,
			boolean critical, ASN1Object value) throws ASN1Exception {
		SEQUENCE extension = new SEQUENCE();
		// extnId
		extension.addComponent(ASN1Factory.encodeASN1Object(new org.keysupport.encoding.Tag(
				org.keysupport.encoding.Tag.OBJECTID), extnId.getEncoded()));
		// Critical assumed default (false), otherwise, add BOOLEAN true
		if (critical) {
			extension.addComponent(new BOOLEAN(true));
		}
		// extnValue
		extension.addComponent(ASN1Factory.encodeASN1Object(new org.keysupport.encoding.Tag(
				org.keysupport.encoding.Tag.OCTETSTRING), value.getBytes()));
		return extension;
	}

	@Override
	public void onClick(View v) {
		// TODO Auto-generated method stub
		
	}

}
