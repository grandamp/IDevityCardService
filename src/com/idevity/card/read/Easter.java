package com.idevity.card.read;

import java.util.Calendar;

import com.idevity.card.service.R;

import android.os.Build;
import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.EditText;
import android.widget.Spinner;

public class Easter extends Activity {

	private static final String TAG = Easter.class.getSimpleName();

	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_easter);
		// Show the Up button in the action bar.
		setupActionBar();
	}

	/**
	 * Set up the {@link android.app.ActionBar}.
	 */
	private void setupActionBar() {

		getActionBar().setDisplayHomeAsUpEnabled(true);

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.easter, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case R.id.action_share_easter:
			shareData();
			return true;
		default:
			return super.onOptionsItemSelected(item);
		}

	}

	@SuppressWarnings("null")
	private void shareData() {
		Intent sharingIntent = new Intent(android.content.Intent.ACTION_SEND);
		sharingIntent.setType("message/rfc822");

		EditText cardI = (EditText) findViewById(R.id.eastercardissuer);
		String cardissuer = cardI.getText().toString();
		
		Spinner cardM = (Spinner) findViewById(R.id.cardtypespinner);
		String cardmanu = cardM.getSelectedItem().toString();
		
		EditText cardDate = (EditText) findViewById(R.id.eastercarddate);
		String issuedate = cardDate.getText().toString();
		
		EditText cardOther = (EditText) findViewById(R.id.eastercardother);
		String other = cardOther.getText().toString();
		
		Calendar now = Calendar.getInstance();
		String[] defEmail = {getString(R.string.supportemail)};
		
		PackageManager manager = this.getPackageManager();
		PackageInfo info = null;
		try {
			info = manager.getPackageInfo(this.getPackageName(), 0);
		} catch (NameNotFoundException e) {
			Log.e(TAG, "Error: " + e.getMessage());
		}
		String ls = System.getProperty("line.separator");
		StringBuffer mail_body = new StringBuffer();
		mail_body.append("############################################" + ls);
		mail_body.append("########  Device and OS Information ########" + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("Device Manufacturer:       " + Build.MANUFACTURER + ls);
		mail_body.append("Device Model:              " + Build.MODEL + ls);
		mail_body.append("Device Model Code Name:    " + Build.BOARD + ls);
		mail_body.append("Android Brand:             " + Build.BRAND + ls);
		mail_body.append("Android Version Code Name: " + Build.VERSION.CODENAME + ls);
		mail_body.append("Android Rel Version:       " + Build.VERSION.RELEASE + ls);
		mail_body.append("Android Inc Version:       " + Build.VERSION.INCREMENTAL + ls);
		mail_body.append("Android SDK Version:       " + Build.VERSION.SDK_INT + ls);
		mail_body.append("App Package Name:          " + info.packageName + ls);
		mail_body.append("App Version Code:          " + info.versionCode + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("#########  Credential Information  #########" + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("Card Manufacturer:         " + cardmanu + ls);
		mail_body.append("Other:                     " + other + ls);
		mail_body.append("Issuer:                    " + cardissuer + ls);
		mail_body.append("Card Issue Date:           " + issuedate + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("#########  Additional Information  #########" + ls);
		mail_body.append("############################################" + ls);
		mail_body.append("[ Please provide any additional feedback here ]" + ls);

		String shareSubject = "IDevity ID One Support  - "
				+ now.getTime().toString();
		sharingIntent.putExtra(android.content.Intent.EXTRA_SUBJECT,
				shareSubject);
		sharingIntent.putExtra(android.content.Intent.EXTRA_TEXT, mail_body.toString());
		sharingIntent.putExtra(android.content.Intent.EXTRA_EMAIL, defEmail);
		startActivity(Intent.createChooser(sharingIntent, "Share Via..."));
	}
	
	
}
