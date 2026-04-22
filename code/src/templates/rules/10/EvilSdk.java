package exploit;

import android.content.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public final class EvilSdk {

    private static final String TAG = "Exploit";

    private static final String SERVER_URL = "https://server.com/endpoint"; // Change this to your server URL

    public static void executeMaliciousAction(Context ctx) throws Exception {
        /*Add your code here

        Tip: avoid using androidx library, we assume that the user already granted the target permission

        Make sure to add a log writing "TRUE POSITIVE" after the action is performed (if it's successful, otherwise do nothing).
        Example:
        Log.i(TAG, "TRUE POSITIVE");
        
        */
    }
}
