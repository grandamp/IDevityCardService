package com.idevity.card.read;

import java.util.Timer;
import java.util.TimerTask;

import com.idevity.card.service.R;

import android.app.Activity;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.view.View;
import android.widget.TextView;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: SplashActivity.java 234 2013-11-09 16:27:17Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 234 $ 
 * 
 * Changed: $LastChangedDate: 2013-11-09 11:27:17 -0500 (Sat, 09 Nov 2013) $
 *****************************************************************************/
public class SplashActivity extends Activity {

	private long splashDelay = 3000; // 3 seconds

	/** Called when the activity is first created. */
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.splash);
		TextView ndw = (TextView) findViewById(R.id.nfc_disabled_warn); 
		ndw.setVisibility(View.INVISIBLE);

		TextView udw = (TextView) findViewById(R.id.plug_in_usb_warn);
		udw.setVisibility(View.INVISIBLE);
		TextView nudw = (TextView) findViewById(R.id.nfc_disabled_warn_or_usb_not_plugged_in);
		nudw.setVisibility(View.INVISIBLE);
		
		/*
		 * Perform NFC Interface check to:
		 * 
		 * -Make sure there is an NFC Interface
		 * -and-
		 * -Show a warning if not NFC is not enabled.
		 * 
		 * If the NFC Interface is not enabled, the NFC
		 * settings will be opened for the user once they
		 * are forwarded to the next activity.
		 */
		NfcAdapter adapter = NfcAdapter.getDefaultAdapter(this);
	    if (adapter == null) {
	    	/*
	    	 * NFC not available on this device,
	    	 * do not allow the app to proceed.
	    	 */
	    	return;
	    }
		if (!adapter.isEnabled()) {
			/*
			 * Set warning to VISIBLE if NFC is not enabled.
			 */
			ndw.setVisibility(View.VISIBLE);
		}

		TimerTask task = new TimerTask() {

			@Override
			public void run() {
				finish();
				Intent mainIntent = new Intent().setClass(SplashActivity.this,
						Read80073.class);
				startActivity(mainIntent);
			}

		};

		Timer timer = new Timer();
		timer.schedule(task, splashDelay);
	}
}