package com.idevity.card.service.applets;

import android.util.Log;

import com.idevity.card.data.CardData80073;

public class PIVApplet extends Applet80073 {
	
	private static final String TAG = PIVApplet.class.getSimpleName();
	
	public PIVApplet(CardData80073 cardData) {
		//Default constructor.  Will be called with CardData80073 Object.
		super.setCardData(cardData);
		Log.d(TAG, "Applet initialized");
		
	}

}
