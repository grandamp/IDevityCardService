package com.idevity.card.read;

import com.idevity.card.service.R;

import android.os.Bundle;
import android.app.Activity;
import android.view.MenuItem;
import android.widget.TextView;
import android.support.v4.app.NavUtils;
import android.text.method.LinkMovementMethod;

/******************************************************************************
 * The following code belongs to IDevity and is provided though commercial
 * license or by acceptance of an NDA only.
 * 
 * $Id: IdevityInfo.java 287 2013-12-17 00:54:16Z tejohnson $
 * 
 * @author Matthew Ambs (matt@idevity.com)
 * @author Eugene Yu (eugene@idevity.com)
 * @author Todd E. Johnson (todd@idevity.com)
 * @author LaChelle Levan (lachelle@idevity.com)
 * 
 * @version $Revision: 287 $ 
 * 
 * Changed: $LastChangedDate: 2013-12-16 19:54:16 -0500 (Mon, 16 Dec 2013) $
 *****************************************************************************/
public class IdevityInfo extends Activity {

	/**
	 * Method onCreate.
	 * 
	 * @param savedInstanceState
	 *            Bundle
	 */
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_idevity_info);
		// Show the Up button in the action bar.
		setupActionBar();
		// Turn URL(s) into a clickable link(s)
		TextView feedback = (TextView) findViewById(R.id.feedback);
		feedback.setMovementMethod(LinkMovementMethod.getInstance());
		TextView website = (TextView) findViewById(R.id.website);
		website.setMovementMethod(LinkMovementMethod.getInstance());
	}

	/**
	 * Set up the {@link android.app.ActionBar}.
	 */
	private void setupActionBar() {
		getActionBar().setDisplayHomeAsUpEnabled(true);
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
		switch (item.getItemId()) {
		case android.R.id.home:
			// This ID represents the Home or Up button. In the case of this
			// activity, the Up button is shown. Use NavUtils to allow users
			// to navigate up one level in the application structure. For
			// more details, see the Navigation pattern on Android Design:
			//
			// http://developer.android.com/design/patterns/navigation.html#up-vs-back
			//
			NavUtils.navigateUpFromSameTask(this);
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

}
