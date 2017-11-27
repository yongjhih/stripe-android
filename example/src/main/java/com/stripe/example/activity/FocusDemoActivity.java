package com.stripe.example.activity;

import android.os.Bundle;
import android.support.annotation.Nullable;
import android.support.v7.app.AppCompatActivity;

import com.stripe.android.view.CardInputWidget;
import com.stripe.example.R;

public class FocusDemoActivity extends AppCompatActivity {
    @Override
    protected void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_focus_demo);
        CardInputWidget cardInputWidget = findViewById(R.id.card_input_widget);
        cardInputWidget.clearFocus();
    }
}
