package com.example.exploittemplate;

import android.os.Bundle;
import android.content.Intent;
import android.util.Log;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

public class MainActivity extends AppCompatActivity {

     private static final String TAG = "Exploit";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        boolean falsePositive = true;
        Intent i = new Intent();
        /*
         * Add your code here
         */
        try {
            startForegroundService(i);
            falsePositive = false;
        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            boolean res = bindService(i);
            Log.i(TAG,"bindService returned: " + res)
            falsePositive = false;
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (falsePositive) {
            Log.e(TAG,"FALSE POSITIVE: Both startService and bindService calls failed, maybe the target is not vulnerable?");
        }
        
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
    }
}
