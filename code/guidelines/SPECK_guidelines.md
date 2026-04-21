# SPECK: From Google Textual Guidelines to Automatic Detection of Android Apps Potential Vulnerabilities

# A RULES

## A.1 Rule 1 - Show an app chooser

Google Guideline: If an implicit intent can launch at least two possible apps on a user’s device, explicitly show an app chooser. This interaction strategy allows users to transfer sensitive information to an app that they trust.

    Intent intent = new Intent(Intent.ACTION_SEND);
    List<ResolveInfo> possibleActivitiesList = queryIntentActivities(intent, PackageManager.MATCH_ALL);

    // Verify that an activity in at least two apps on

    // the user 's device can handle the intent.

    // Otherwise , start the intent only if an app on

    // the user 's device can handle the intent .
    if (possibleActivitiesList.size () > 1) {

        // Create intent to show chooser.
        // Title is something similar to "Share this photo with".

        String title = getResources().getString(R.string.chooser_title);
        Intent chooser = Intent.createChooser(intent, title);
        startActivity(chooser);

    } else if (intent.resolveActivity(getPackageManager()) != null) {
        startActivity(intent);
    }

Listing 8. Show an app chooser

Rule design: The logic of Rule 1 is shown in Algorithm 1 where we inspect all implicit intents used by an
app, and verify that Intent.createChooser() is called on these intents. If an Intent is constructed as implicit, but Intent.createChooser() is not called on that intent, we mark it as a violation.

Algorithm 7: Show an app chooser

    begin
        implicitIntents ← getAppImplicitIntents()
        chooserIntents ← getAppChooserIntents()
        foreach intent in implicitIntents do

            if intent not in chooserIntents then
                Rule 1 is not respected.
            end
        end
    end

Attack: The attack aims at intercepting an implicit Intent, that is originally sent to a legitimate app, but that is intercepted by a malicious one without any user notification. To complete the attack, a malicious app exploits the implicit Intent forwarding system of the Android OS and the absence of an app chooser. Thus, by declaring the Intent Filter associated to the target implicit Intent with the highest priority, the malicious app becomes the recipient of the implicit Intent, which will be successfully delivered to the malicious app since no app chooser will be shown.

## A.2 Rule 2 - Protect the access to Content Providers

A.2.1 Apply signature-based permissions. Google guideline: When sharing data between two apps that you control or own, use signature-based permissions. These permissions don’t require user confirmation and instead check that the apps accessing the data are signed using the same signing key. Therefore, these permissions offer a more streamlined, secure user experience.

    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.myapp">

    <permission
    android:name="my_custom_permission_name"
    android:protectionLevel ="signature"/>

Listing 9. Apply signature-based permissions

A.2.2 Disallow access to your app’s content providers. Google guideline: Unless you intend to send data from your app to a different app that you don’t own, you should explicitly disallow other developers’ apps from accessing the
ContentProvider objects that your app contains. This setting is particularly important if your app can be installed on
devices running Android 4.1.1 (API level 16) or lower, as the android:exported attribute of the <provider> element is
true by default on those versions of Android.

    <manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.myapp">

    <application ... >

    <provider
    android:name="android.support.v4.content.FileProvider"
    android:authorities="com.example.myapp.fileprovider"
    ...
    android:exported="false">

    <!--Place child elements of <provider> here.-->

    </provider>

    ...

    </application>

    </manifest>

Listing 10. Disallow access to your app’s content providers

Rule design: The logic of Rule 2 is shown in Algorithm 2. We inspect the app manifest to obtain the list of exported
Content Providers. If a declared Content Provider is exported, but is not protected by a custom permission, we warn the user.

Algorithm 2: Content provider access control

    begin
        providers ← getContentProviderObjs()
        apiLevel ← getMinApiLevel()
        foreach provider in providers do
        if isExported(provider, apiLevel) then
            if isExported(provider, apiLevel) then
                if not usesCustomPermission(provider) then
                    Rule 2 is not respected.
                end
            end
        end
    end

Attack: If a ContentProvider object is exported and not permission-protected, any other app on the same device can interact with it, by launching SQL injection attacks, reading or modifying its data.

## A.3 Rule 3 - Only request the needed permissions

Google guideline: Your app should request only the minimum number of permissions necessary to function properly. When possible, your app should relinquish some of these permissions when they’re no longer needed.

Rule design: The logic of Rule 3 is shown in Algorithm 3. We collect the list of permissions requested by an app
from its manifest, and check if any of the APIs requiring such permissions are invoked by inspecting the app source code (for the mapping between APIs and permissions we rely on axplorer
we consider it a vulnerability.

If a permission is requested, but not used, it is considered a violation to the rule.

Algorithm 3: Provide the right permissions

    begin
        permissions ← getAllPermissions()
        foreach perm in permissions do
            sdkFuncs ← getSdkFuncs(perm)
            uriContProvs ← getURIContProvs(perm)
            names ← sdkFuncs + uriContProvs
            called ← getCalledMethods(names)
            if isEmpty(called) then
                Rule 3 is not respected.
            end
        end
    end

Attack: To access protected resources on a mobile device, an app has to declare the associated permissions. Any code
running within the same UID has access to the same set of protected resources, defined according to the permissions declared by the app. This can also happen for third-party libraries, which an app might include to have additional features. The higher the number of permissions declared by an app, the higher the risk for the whole mobile device to get attacked by malicious code running within the same UID of that app.

## A.4 Rule 4 - Use intents to defer permissions

Google guideline: Whenever possible, don’t add a permission to your app to complete an action that could be completed in another app. Instead, use an intent to defer the request to a different app that already has the necessary permission.
The following example shows how to use an intent to direct users to a contacts app instead of requesting the READ_CONTACTS
and WRITE_CONTACTS permissions:

    // Delegates the responsibility of creating the
    // contact to a contacts app , which has already
    // been granted the appropriate WRITE_CONTACTS permission.

    Intent insertContactIntent = new Intent(Intent.ACTION_INSERT);
    insertContactIntent.setType(ContactsContract.Contacts.CONTENT_TYPE);

    // Make sure that the user has a contacts app installed on their device.

    if (insertContactIntent.resolveActivity(getPackageManager()) != null) {
        startActivity(insertContactIntent);
    }

Listing 11. Use intents to defer permissions

In addition, if your app needs to perform file-based I/O – such as accessing storage or choosing a file – it doesn’t need special permissions because the system can complete the operations on your app’s behalf. Better still, after a user selects content at a particular URI, the calling app is granted permission to the selected resource.

Rule design: The logic of Rule 4 is shown in Algorithm 4. We get the list of permissions requested by the app from its manifest, and compare it with a “blacklist” of permissions for the actions that could be completed by other apps (e.g. instead of requesting the SEND_SMS permission, an app can delegate the action to the SMS app). If the app requests any of the blacklisted permissions, we consider it a violation to the rule.

Algorithm 4: Use intents to defer permissions

    begin
        permissions ← getAllPermissions()
        foreach perm in permissions do
            if perm in blacklist then
                Rule 4 is not respected.
            end
        end
    end

Attack: To access protected resources on a mobile device, an app has to declare the associated permissions. Any code
running within the same UID has access to the same set of protected resources, defined according to the permissions declared by the app. This can also happen for third-party libraries, which an app might include to have additional features. The higher the number of permissions declared by an app, the higher the risk for the whole mobile device to get attacked by malicious code running within the same UID of that app.

## A.5 Rule 5 - Use SSL traffic

Google Guideline: If your app communicates with a web server that has a certificate issued by a well-known, trusted CA, the HTTPS request is very simple:

    URL url = new URL ("https://www.google.com");
    HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();

    urlConnection.connect();

    InputStream in = urlConnection.getInputStream();

Listing 12. Use SSL traffic

Rule design: The logic of Rule 5 is shown in Algorithm 5. We first search for invocations of the URL.openConnection() method. If the return value of such invocations is cast to HttpURLConnection and not to HttpsURLConnection, we consider it a violation. Additionally, we check if the connections have a TrustManager or handle the exceptions.

Algorithm 5: Use SSL traffic

    begin
        openConns ← getOpenConnVars()
        httpsOpenConns ← getHttpsOpenConnVars()
        httpsConnSSLs ← getConnSSLSockFactVars()
        foreach openConn in openConns do

            if openConn not in httpsOpenCons then
                Rule 5 is not respected.
            end
            if openConn not in httpsConnSSLs and not catchesException(openConn) then
                Rule 5 is not respected.
            end
        end
    end

Attack: The SSLSocketFactory can be used to validate the identity of an HTTPS server against a list of trusted certificates and to authenticate to the HTTPS server using a private key. If HTTPS is not used, or it is used without a validation of the HTTPS server through the SSLSocketFactory, a Man-in-the-Middle attack can be performed, i.e., an attacker can secretly relay and alter the communication between two parties.

## A.6 Rule 6 - Do not use WebView Javascript Interface

Google Guideline: Because WebView consumes web content that can include HTML and Javascript, improper use can introduce common web security issues such as cross-site-scripting (Javascript injection). Android includes a number of mechanisms to reduce the scope of these potential issues by limiting the capability of WebView to the minimum functionality required by your application. If your application doesn’t directly use Javascript within a WebView, do not call setJavascriptEnabled(). Some sample code uses this method, which you might repurpose in production application, so remove that method call if it’s not required. By default, WebView does not execute Javascript, so cross-site-scripting is not possible. Use addJavascriptInterface() with particular care because it allows Javascript to invoke operations that are normally reserved for Android applications. If you use it, expose addJavascriptInterface() only to web pages from which all input is trustworthy. If untrusted input is allowed, untrusted Javascript may be able to invoke Android methods within your app. In general, we recommend exposing addJavascriptInterface() only to Javascript that is contained within your application APK.

If your app must use Javascript interface support on devices running Android 6.0 (API level 23) and higher, use HTML message channels instead to communicate between a website and your app, as shown in the following code snippet:

    WebView myWebView = (WebView) findViewById (R.id.webview);

    // messagePorts [0] and messagePorts [1] represent
    // the two ports . They are already tangled to each
    // other and have been started.

    WebMessagePort[] channel = myWebView.createWebMessageChannel();

    // Create handler for channel [0] to receive

    // messages .
    channel[0].setWebMessageCallback(new WebMessagePort.WebMessageCallback() {

        @Override
        public void onMessage ( WebMessagePort port , WebMessage message ) {

        Log.d(TAG, "On port " + port + ", received this message: " + message);

        }

    }) ;

    // Send a message from channel [1] to channel [0].
    channel[1].postMessage(new WebMessage("My secure message"));

Listing 13. Use HTML message channels

Rule design: The logic of Rule 6 is shown in Algorithm 6. We check if the app calls any method to enable or evaluate JavaScript code inside a WebView object.

Algorithm 6: Use HTML message channels

    begin
        s1 ← “setJavascriptEnabled”
        s2 ← “true”
        arr ← [“evaluateJavascript”, “addJavascriptInterface”]
        methods ← getAllCalledMethods()
        foreach method in methods do
            if method in arr then
                Rule 6 is not respected.
            end
            if method = s1 then
                if getSecondArg(method) = s2 then
                    Rule 6 is not respected.
                end
            end
        end
    end

Attack: An insecure handling of Javascript code can lead to XSS attacks.

## A.7 Rule 7 - Use WebView objects carefully

Google guideline: Whenever possible, load only whitelisted content in WebView objects. In other words, the WebView objects in your app shouldn’t allow users to navigate to sites that are outside of your control.

Rule design: The logic of Rule 7 is shown in Algorithm 7. Developers can use a custom WebViewClient to check the URLs that a WebView loads. We find violations to Rule 7 by checking if an app has any WebView object that does not use a custom WebViewClient to check the loaded URLs.

Attack: WebView objects are responsible for rendering the web code either belonging to external resources (e.g., a website) or saved in an app. If a WebView object loads any website and does not refer to a specific whitelist, an attacker might make the WebView object load a malicious website, which has JavaScript code running on the client side and able to steal sensitive information (e.g., cookies).

Algorithm 7: Use WebView objects carefully

    begin
        webViews ← getAllWebViewVars() w
        whitelistedViews ← getSetWebViewClient() 
        foreach view in webViews do
            if view not in whitelistedViews or not isOverridingUrlLoading(view) then
                Rule 7 is not respected.
            end
        end
    end


## A.8 Rule 8 - Store private data within internal storage

Google guideline: Store all private user data within the device’s internal storage, which is sandboxed per app. Your app doesn’t need to request permission to view these files, and other apps cannot access the files. As an added security measure, when the user uninstalls an app, the device deletes all files that the app saved within internal storage.

The following code snippet demonstrates one way to write data to storage:

    // Creates a file with this name , or replaces an
    // existing file that has the same name . Note that
    // the file name cannot contain path separators .

    final String FILE_NAME = "sensitive_info.txt";
    String fileContents = "This is some top-secret information!";

    FileOutputStream fos = openFileOutput(FILE_NAME, Context.MODE_PRIVATE);
    fos.write(fileContents.getBytes());

    fos.close();

Listing 14. Write data to the internal storage

The following code snippet shows the inverse operation, reading data from storage:

    // The file name cannot contain path separators .
    final String FILE_NAME = "sensitive_info.txt";
    FileInputStream fis = openFileInput(FILE_NAME);

    // available() determines the approximate number of
    // bytes that can be read without blocking.
    
    int bytesAvailable = fis.available();
    StringBuilder topSecretFileContents = new StringBuilder(bytesAvailable);

    // Make sure that read() returns a number of bytes
    // that is equal to the file 's size.
    byte[] fileBuffer = new byte[bytesAvailable];
    while (fis.read(fileBuffer) != -1) {
        topSecretFileContents.append(fileBuffer);
    }

Listing 15. Read data from the internal storage

Rule design: The logic of Rule 8 is shown in Algorithm 8. We check if all output files are opened in private mode. If any output file is opened in a different mode, we consider it a violation to the rule.

Algorithm 8: Store private data within internal storage

    begin
        s1 ← “openFileOutput”
        s2 ← "MODE_PRIVATE"
        methods ← getAllCalledMethods()
        foreach method in methods do
            if method = s1 then
                mode ← getModeArg(method)
                if not mode = s2 then
                    Rule 8 is not respected.
                end
            end
        end
    end

Attack: An attacker can read and pollute data since they are not stored in the app private internal storage. Moreover, through a a Man-in-the-Disk attack, an attacker can intercept and potentially alter data while they are extracted by an app from the external storage.

## A.9 Rule 9 - Share data securely across apps

Google guideline: Follow these best practices in order to share your app’s content with other apps in a more secure manner:
-  Enforce read-only or write-only permissions as needed.
-  Provide clients one-time access to data by using the FLAG_GRANT_READ_URI_PERMISSION and FLAG_GRANT_WRITE_URI_PERMISSION flags.
-  When sharing data, use "content://" URIs, not "file://" URIs. Instances of FileProvider do this for you.

The following code snippet shows how to use URI permission grant flags and content provider permissions to display an app’s PDF file in a separate PDF Viewer app:

    // Create an Intent to launch a PDF viewer for a
    // file owned by this app.
    Intent viewPdfIntent = new Intent(Intent.ACTION_VIEW);
    viewPdfIntent.setData(Uri.parse("content://com.example/personal-info.pdf"));

    // This flag gives the started app read access to
    // the file.

    viewPdfIntent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);

    // Make sure that the user has a PDF viewer app

    // installed on their device.
    if (viewPdfIntent.resolveActivity(getPackageManager()) != null) {
        startActivity(viewPdfIntent);
    }

Listing 16. Share data securely across apps

Rule design: The logic of Rule 9 is shown in Algorithm 9. We check if the app passes “file://” URIs to other applications using Intents. If this occurs, we consider it a violation to the rule.

Algorithm 9: Share data securely across apps

    begin
        str ← “file:/”
        arr ← [“FLAG_GRANT_READ_URI_PERMISSION”, “FLAG_GRANT_WRITE_URI_PERMISSION”]
        setDataIntents ← getSetDataIntents()
        foreach intent in setDataIntents do
            uriScheme ← getURIScheme(intent)
            if uriScheme = str then
                Rule 9 is not respected.
            end
        end
    end

Attack: URI permissions can be used to grant other apps access to specific URIs. These permissions are temporary and expire automatically when the receiving app’s task stack is finished. However, to share a file with another application using a file:// URI, the file system permissions need to be changed, allowing anyone to access the file.

## A.10 Rule 10 - Use scoped directory access

Google guideline: If your app needs to access only a specific directory within the device’s external storage, you can use scoped directory access to limit your app’s access to a device’s external storage accordingly. As a convenience to users, your app should save the directory access URI so that users don’t need to approve access to the directory every time your app attempts to access it.

Note: if you use scoped directory access with a particular directory in external storage, know that the user might eject the media containing this storage while your app is running. You should include logic to gracefully handle the change to the Environment.getExternalStorageState() return value that this user behaviour causes.

The following code snippet uses scoped directory access with the pictures directory within a device’s primary shared storage:

    private static final int PICTURES_DIR_ACCESS_REQUEST_CODE = 42;
    private void accessExternalPicturesDirectory () {

        StorageManager sm = (StorageManager) getSystemService(Context.STORAGE_SERVICE);

        StorageVolume = sm.getPrimaryStorageVolume();

        Intent intent = volume.createAccessIntent(Environment.DIRECTORY_PICTURES);

        startActivityForResult(intent, PICTURES_DIR_ACCESS_REQUEST_CODE);

    }

    ...

    @Override
    public void onActivityResult (int requestCode ,int resultCode ,Intent resultData ) {
        if ( requestCode == PICTURES_DIR_ACCESS_REQUEST_CODE && resultCode == Activity.RESULT_OK ) {

        // User approved access to scoped directory in your app
        if ( resultData != null ) {

            Uri picturesDirUri = resultData.getData();

            // Save user's approval for accessing this
            // directory in your app

            ContentResolver myContentResolver = getContentResolver();
            myContentResolver.takePersistableUriPermission(picturesDirUri, Intent.FLAG_GRANT_READ_URI_PERMISSION);
            }
        }
    }

Listing 17. Use scoped directory access

Warning: don’t pass null into createAccessIntent() unnecessarily because this grants your app access to the entire volume that StorageManager finds for your app.

Rule design: The logic of Rule 10 is shown in Algorithm 10. We check if the app requests external storage permissions. If it does, we consider it a violation to the rule.

Algorithm 10: Use scoped directory access

    begin
        arr ← [“READ_EXTERNAL_STORAGE”, “WRITE_EXTERNAL_STORAGE”]
        permissions ← getAllPermissions()
        foreach perm in permissions do
            if perm in arr then
                Rule 10 is not respected.
            end
        end
    end

Attack: As for Rule 3, according to which an app should declare the minimum number of permissions, Rule 10 aims to prevent any malicious code running within the same UID of the app from having access to the whole external storage. Thus, if Rule 10 is not respected and the app has access to the external storage, any malicious code running inside it can not only compromise the app files, but also the ones belonging to other apps.

## A.11 Rule 11 - Store only non-sensitive data in cache files

Google Guideline: To provide quicker access to non-sensitive app data, store it in the device’s cache. For caches larger than 1 MB in size, use getExternalCacheDir(); otherwise, use getCacheDir(). Each method provides you with the File object that contains your app’s cached data.

The following code snippet shows how to cache a file that your app recently downloaded:

    File cacheDir = getCacheDir();
    File fileToCache = new File(myDownloadedFileUri);

    String fileToCacheName = fileToCache.getName();
    File cacheFile = new File(cacheDir.getPath(), fileToCacheName);

Listing 18. Store only non-sensitive data in cache files

Note: if you use getExternalCacheDir() to place your app’s cache within shared storage, the user might eject the media containing this storage while your app is running. You should include logic to gracefully handle the cache miss that this user behavior causes.

Caution: there is no security enforced on these files. Therefore, any app that has the WRITE_EXTERNAL_STORAGE permission can access the contents of this cache.

Rule design: The logic of Rule 11 is shown in Algorithm 11. We check if the app calls the getExternalCacheDir method, and if it does, we show a warning that reminds the developer that sensitive data should not be saved in the device external cache.

Algorithm 11: Store only non-sensitive data in cache files

    begin
        s1 ← “getExternalCacheDir”
        methods ← getAllCalledMethods()
        if s1 in methods then
            Rule 11 is not respected.
        end
    end

Attack: A malicious app can access any data saved in the device external cache, including sensitive data. The directory returned by getExternalCacheDir() is an external storage directory accessible by any other app on the same device.

## A.12 Rule 12 - Use SharedPreferences in private mode

Google guideline: When using creating or accessing your app’s SharedPreferences objects, use MODE_PRIVATE. That way, only your app can access the information within the shared preferences file.
If you want to share data across apps, don’t use Shared-Preferences objects. Instead, you should follow the necessary steps to share data securely across apps.

Rule design: The logic of Rule 12 is shown in Algorithm 12. We get the list of SharedPreferences objects opened by the app, and verify that they are opened in private mode. If any of the SharedPreferences objects is opened in a different mode, we consider it a violation to the rule.

Attack: If an app accesses to its SharedPreferences without the MODE_PRIVATE, a malicious app on the same device can access the same and read/modify the stored information.

Algorithm 12: Use SharedPreferences in private mode

    begin
        s1 ← [“getSharedPreferences”, “getPreferences”]
        s2 ← "MODE_PRIVATE"
        methods ← getAllCalledMethods()
        foreach method in methods do
            if method in s1 then
                mode ← getModeArg(method)
                if not mode = s2 then
                    Rule 12 is not respected.
                end
            end
        end
    end

## A.13 Rule 13 - Check validity of external storage data

Google guideline: If your app uses data from external storage, make sure that the contents of the data haven’t been corrupted or modified. Your app should also include logic to handle files that are no longer in a stable format.

An example of a hash verifier appears in the following code snippet:

    Executor threadPoolExecutor = Executors.newFixedThreadPool(4);
    private interface HashCallback {
        void onHashCalculated(@Nullable String hash);
    }

    boolean hashRunning = calculateHash(inputStream, threadPoolExecutor, hash -> {

        if (Objects.equals(hash, expectedHash)) {
            // Work with the content.
        }

    });

    if (!hashRunning) {
        // There was an error setting up the hash function.
    }

    private boolean calculateHash(@NonNull InputStream stream, @NonNull Executor executor, @NonNull HashCallback hashCallback) {

        final MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException nsa) {
            return false;
        }
        // Calculating the hash code can take quite a bit
        // of time, so it shouldn 't be done on the main
        // thread.
        executor.execute(() -> {
            String hash;
            try (DigestInputStream digestStream = new DigestInputStream(stream, digest)) {
                while (digestStream.read() != -1) {
                    // The DigestInputStream does the work;
                    // nothing for us to do.

                }
                StringBuilder builder = new StringBuilder();
                for (byte aByte : digest.digest()) {
                    builder.append(String.format("%02x", aByte)).append(':');
                }
                hash = builder.substring(0, builder.length() - 1);
            } catch (IOException e) {
                hash = null;
            }
            final String calculatedHash = hash;
            runOnUiThread(() -> hashCallback.onHashCalculated(calculatedHash));
        });
        return true;
    }

Listing 19. Check validity of data

Rule design: The logic of Rule 13 is shown in Algorithm 13. We check if the app reads any file from the external storage. If this is so, we show a warning stating that the app should check the validity of the data read from those files.

Algorithm 13: Check validity of data

    begin
        str ← “READ_EXTERNAL_STORAGE”
        permissions ← getAllPermissions()
        if str in permissions then
            vars ← getAllFileInputVars()
                foreach var in vars do
                if isExternalStorageDir(var) then
                    Rule 13 is not respected.
                end
            end
        end
    end

Attack: If an app does not check the validity of the data stored on the external storage, it might not rely that some data could have been tampered with by a malicious app on the same device.

## A.14 Rule 14 - Do not create dangerous permissions

Google guideline: Generally, you should strive to define as few permissions as possible while satisfying your security requirements. Creating a new permission is relatively uncommon for most applications, because the system-defined permissions cover many situations. Where appropriate, perform access checks using existing permissions.

If you must create a new permission, consider whether you can accomplish your task with a signature protection level. Signature permissions are transparent to the user and allow access only by applications signed by the same developer as the application performing the permission check. If the new permission is still required, it’s declared in the app manifest using the <permission> element. Apps that wish to use the new permission can reference it by each adding a <uses-permission> element in their respective manifest files. You can also add permissions dynamically by using the addPermission() method.
If you create a permission with the dangerous protection level, there are a number of complexities that you need to consider:

- The permission must have a string that concisely expresses to a user the security decision they are required to make.
- The permission string must be localized to many different languages.
- Users may choose not to install an application because a permission is confusing or perceived as risky.
- Applications may request the permission when the creator of the permission has not been installed.

Each of these poses a significant nontechnical challenge for you as the developer while also confusing your users, which is why we discourages the use of the dangerous permission level.

Rule design: The logic of Rule 14 is shown in Algorithm 14. We collect the list of custom permissions declared in the manifest. If any of these permissions is declared as dangerous, we consider it a violation to the rule.

Algorithm 14: Create permissions

    begin
        str ← “dangerous”
        permissions ← getCustomPermissions()
        foreach perm in permissions do
            if getPermProtectLevel(perm) = str then
                Rule 14 is not respected.
            end
        end
    end

Attack: Defining new permissions without the signature protection level might lead to a lack of access control to protected resources. Any malicious app can declare the new permission and exploit it, since no control over the signature will be applied.

## A.15 Rule 15 - Erase data in WebView cache

Google Guideline: If your application accesses sensitive data with a WebView, you may want to use the clearCache() method to delete any files stored locally. You can also use server-side headers such as no-cache to indicate that an application should not cache particular content.

Rule design: The logic of Rule 15 is shown in Algorithm 15. We check if the app clears the cache of all the WebView object it uses.

Attack: If an app using a WebView object and does not clear its cache through the clearCache() method, any malicious code running within the app UID (e.g., third-party libraries) can access to the data saved in the cache.

Algorithm 15: Erase data in webview cache

    begin
        webViews ← getAllWebViewVars()
        foreach webView in webViews do
            if not usesClearCache(webView) then
                Rule 15 is not respected.
            end
        end
    end

## A.16 Rule 16 - Avoid SQL injections

Google Guideline: When accessing a content provider, use parameterized query methods such as query(), update(), and delete() to avoid potential SQL injection from untrusted sources. Note that using parameterized methods is not sufficient if the selection argument is built by concatenating user data prior to submitting it to the method.
Don’t have a false sense of security about the write permission. The write permission allows SQL statements that make it possible for some data to be confirmed using creative WHERE clauses and parsing the results. For example, an attacker might probe for the presence of a specific phone number in a call log by modifying a row only if that phone number already exists.

If the content provider data has predictable structure, the write permission may be equivalent to providing both reading and writing.

Rule design: The logic of Rule 16 is shown in Algorithm 16. If the query() method of a Content Provider is overridden, the user input should be properly validated to avoid SQL injections. For this reason, we check if the app contains Content Providers that redefine the query() method, and if it does, we show a warning reminding the user that the input should be properly validated.

Algorithm 16: Avoid SQL injections: use content providers

    begin
        str ← “query”
        extendCP ← getClassesExtendCP()
        foreach obj in extendCP do
            methods ← getObjMethods(obj)
                foreach method in methods do
                if method = str then
                    Rule 16 is not respected.
                end
            end
        end
    end

Attack: If an app uses parameterized query methods to access one of its content providers, but the selection argument is built by concatenating user data, an attacker can launch SQL injection attacks.

## A.17 Rule 17 - Prefer explicit intents

Google Guideline: For activities and broadcast receivers, intents are the preferred mechanism for asynchronous IPC in Android. Depending on your application requirements, you might use sendBroadcast(), sendOrderedBroadcast(), or an explicit intent to a specific application component. For security purposes, explicit intents are preferred.

Caution: if you use an intent to bind to a Service, ensure that your app is secure by using an explicit intent. Using an
implicit intent to start a service is a security hazard because you can’t be certain what service will respond to the intent, and the user can’t see which service starts. Beginning with Android 5.0 (API level 21), the system throws an exception if you call bindService() with an implicit intent.

Note that ordered broadcasts can be consumed by a recipient, so they may not be delivered to all applications. If you are sending an intent that must be delivered to a specific receiver, you must use an explicit intent that declares the receiver by name.

Senders of an intent can verify that the recipient has permission by specifying a non-null permission with the method call.

Only applications with that permission receive the intent. If data within a broadcast intent may be sensitive, you should consider applying a permission to make sure that malicious applications can’t register to receive those messages without appropriate permissions. In those circumstances, you may also consider invoking the receiver directly, rather than raising a broadcast.

Rule design: The logic of Rule 17 is shown in Algorithm 17. We check all the intents the app uses to send broadcast messages, start or bind services, or start activities. If any of these intents is implicit, we consider it a violation to the rule.

Algorithm 17: Prefer explicit intents

    begin
        bindNames ← getBindNamesIntents()
        startService ← getStartServiceIntents()
        sendOrdBcast ← getSendOrdBcastIntents()
        startActivity ← getStartActivityIntents()
        intents ← bindNames + startService + sendOrdBcast + startActivity
        foreach intent in intents do
            if not isExplicit(intent) then
                Rule 17 is not respected.
            end
        end
    end

Attack: The attack is the same as for Rule 1.

## A.18 Rule 18 - Do not use IP networking for IPC

Google guideline: Some applications use localhost network ports for handling sensitive IPC. You should not use this approach because these interfaces are accessible by other applications on the device. Instead, use an Android IPC mechanism where authentication is possible, such as with a Service. Binding to INADDR_ANY is worse than using loopback because then your application may receive requests from anywhere.

Rule design: The logic of Rule 18 is shown in Algorithm 18. We look for reference to local addresses (e.g. “localhost”) in the code of the app. If we find any, we consider it a violation to the rule.

Algorithm 18: Use IP networking

    begin
        arr ← [“INADDR_ANY”, “localhost”, “127.0.0.1”]
        javaCode ← getAllJavaCode()
        foreach word in javaCode do
            if word in arr then
                Rule 18 is not respected.
            end
        end
    end

Attack: A malicious app can connect to the same localhost network ports as legitimate apps and intercept the messages they exchange.

## A.19 Rule 19 - Do not export unprotected services

Google guideline: A Service is often used to supply functionality for other applications to use. Each service class must have a corresponding <service> declaration in its manifest file.
By default, services are not exported and cannot be invoked by any other application. However, if you add any intent filters to the service declaration, it is exported by default. It’s best if you explicitly declare the android:exported attribute to be sure it behaves as you’d like. Services can also be protected using the android:permission attribute. By doing so, other applications need to declare a corresponding <uses-permission> element in their own manifest to be able to start, stop, or bind to the service.
A service can protect individual IPC calls into it with permissions, by calling checkCallingPermission() before executing the implementation of that call. You should use the declarative permissions in the manifest, since those are less prone to oversight.

Caution: don’t confuse client and server permissions; ensure that the called app has appropriate permissions and verify that you grant the same permissions to the calling app.

Rule design: The logic of Rule 19 is shown in Algorithm 19. We look at the services that an app exports. If the app contains any implicitly exported service, or if any of the exported services does not check for permissions, we consider it a violation to the rule.

Algorithm 19: Use services

    begin
        services ← getAllServices()
        foreach svc in services do
            if hasIntentFilter(svc) and not isExported(svc) then
                Rule 19 is not respected.
            end
            if isExported(svc) then
                if not hasPerm(svc) and not checksCallingPerm(svc) then
                    Rule 19 is not respected.
                end
            end
        end
    end

Attack: If a Service is exported, a malicious app can interact with it by sending malicious Intent messages, that compromise the Service runtime execution.

## A.20 Rule 20 - Do not use telephony networking for sensitive data

Google guideline: The SMS protocol was primarily designed for user-to-user communication and is not well-suited for apps that want to transfer data. Due to the limitations of SMS, you should use Google Cloud Messaging (GCM) and IP networking for sending data messages from a web server to your app on a user device.

Beware that SMS is neither encrypted nor strongly authenticated on either the network or the device. In particular, any SMS receiver should expect that a malicious user may have sent the SMS to your application. Don’t rely on unauthenticated SMS data to perform sensitive commands. Also, you should be aware that SMS may be subject to spoofing and/or interception on the network. On the Android-powered device itself, SMS messages are transmitted as broadcast intents, so they may be read or captured by other applications that have the READ_SMS permission.

Rule design: The logic of Rule 20 is shown in Algorithm 20. Since an app may use SMS for legitimate reasons, we check the manifest of the app and look for SMS-related permissions. If we find any, we remind the user that SMS are inherently insecure and should not be trusted or used to send sensitive information.

Algorithm 20: Use telephony networking

    begin
        arr ← [“SEND_SMS”, “READ_SMS”, “RECEIVE_SMS”]
        permissions ← getAllPermissions()
        foreach perm in permissions do
            if perm in arr then
                Rule 20 is not respected.
            end
        end
    end

Attack: An attacker could use sms spoofing to send a malicious SMS to a legitimate app. Alternatively, an attacker could intercept the SMS messages sent by a legitimate app and read their content, which is not encrypted.

## A.21 Rule 21 - Use secure random number generators for cryptographic keys

Google guideline: Use a secure random number generator, SecureRandom, to initialize any cryptographic keys generated
by KeyGenerator. Use of a key that is not generated with a secure random number generator significantly weakens the
strength of the algorithm and may allow offline attacks.
If you need to store a key for repeated use, use a mechanism, such as KeyStore, that provides a mechanism for long term
storage and retrieval of cryptographic keys.

Rule design. The logic of Rule 21 is shown in Algorithm 21. We look for KeyGenerator objects in the code of the app.
If any of these objects is non initialized using a secure random number generator, we cosider it a violation to the rule.
Attack. When keys are not generated through secure random number generators, a malicious app can infer the value of such keys and decrypt any sensitive data previously encrypted by the legitimate app.

Algorithm 21: Use cryptography

    begin
        keyGens ← getAllKeyGenVars()
        secRands ← getAllSecRandVars()
        foreach keyGen in keyGens do
            if not initsWithAny(keyGen, secRands) then
                Rule 21 is not respected.
            end
        end
    end

## A.22 Rule 22 - Protect exported Broadcast Receivers

Google Guideline: A BroadcastReceiver handles asynchronous requests initiated by an Intent.
By default, receivers are exported and can be invoked by any other application. If your BroadcastReceiver is intended for use by other applications, you may want to apply security permissions to receivers using the <receiver> element within the application manifest. This prevents applications without appropriate permissions from sending an intent to the BroadcastReceiver.

Rule design: The logic of Rule 22 is shown in Algorithm 22. We inspect all Broadcast Receivers declared by the app.

If there is any Broadcast Receiver that is not protected by a permission, we consider it a violation to the rule.

Algorithm 22: Use broadcast receivers

    begin
        receivers ← getAllBcastReceivers()
        foreach receiver in receivers do
            if isExported(receiver) then
                if not hasPermission(receiver) then
                    Rule 22 is not respected.
                end
            end
        end
    end

Attack: Any malicious app can create an intent which can trigger an exported receiver not protected by a permission. For instance, let’s consider an exported and not protected receiver which sends an SMS to a phone number received as an extra parameter of the triggering intent. A malicious application could trigger the receiver by sending intents with a premium rate SMS number. Thus, it would force users to send messages without their consent, stealing money from them.

## A.23 Rule 23 - Do not load code dynamically

Google guideline: We strongly discourage loading code from outside of your application APK. Doing so significantly increases the likelihood of application compromise due to code injection or code tampering. It also adds complexity around version management and application testing. It can also make it impossible to verify the behavior of an application, so it may be prohibited in some environments.

If your application does dynamically load code, the most important thing to keep in mind about dynamically-loaded code is that it runs with the same security permissions as the application APK. The user makes a decision to install your application based on your identity, and the user expects that you provide any code run within the application, including code that is dynamically loaded.

The major security risk associated with dynamically loading code is that the code needs to come from a verifiable source. If the modules are included directly within your APK, they cannot be modified by other applications. This is true whether the code is a native library or a class being loaded using DexClassLoader. Many applications attempt to load code from insecure locations, such as downloaded from the network over unencrypted protocols or from world-writable locations such as external storage. These locations could allow someone on the network to modify the content in transit or another application on a user’s device to modify the content on the device.

Rule design: The logic of Rule 23 is shown in Algorithm 23. We search for any invocation to the DexClassLoader class and consider it a violation to the rule.

Algorithm 23: Dynamically load code

    begin
        str ← “DexClassLoader”
        javaCode ← getAllJavaCode()
        foreach word in javaCode do
            if word = str then
                Rule 23 is not respected.
            end
        end
    end

Attack: A malicious app can launch a code injection attack through which it modifies the code that a legitimate app will dynamically load. This aim can be achieved if the code is saved in the external storage, is downloaded from a remote location (and, thus, intercepted and modified).

## A.24 Rule 24 - Do not disable hostname verification

Google guideline: Caution: Replacing HostnameVerifier can be very dangerous if the other virtual host is not under your control, because a man-in-the-middle attack could direct traffic to another server without your knowledge.

If you are still sure you want to override hostname verification, here is an example that replaces the verifier for a single URLConnection with one that still verifies that the hostname is at least on expected by the app:

    // Create an HostnameVerifier that hardwires the
    // expected hostname. Note that is different than
    // the URL's hostname: example.com versus example.org
    HostnameVerifier verifier = new HostnameVerifier () {

        @Override
        public boolean verify (String hostname, SSLSession session) {
            HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();
            return hv.verify("example.com", session);
        }

    };

    // Tell the URLConnection to use our HostnameVerifier
    URL url = new URL("https://example.org/");
    HttpsURLConnection urlConnection = (HttpsURLConnection) url.openConnection();
    urlConnection.setHostnameVerifier(verifier);
    InputStream in = urlConnection.getInputStream();
    copyInputStreamToOutputStream(in, System.out);

Listing 20. problems with hostname verification

Rule design: The logic of Rule 24 is shown in Algorithm 24. We look for HttpsUrlConnection objects used by the app. If any of them overrides the default hostname verifier, we consider it a violation to the rule.

Algorithm 24: Common problems with hostname verification

    begin
        connections ← getAllHttpsUrlConnections()
        foreach connection in connections do
            if hasSetHostnameVerifier(connection) then
                Rule 24 is not respected.
            end
        end
    end

Attack: A malicious app can perform a man-in-the-middle attack by redirecting the traffic, originally sent to a legitimate server, towards another malicious one.

## A.25 Rule 25 - Do hostname verification when using SSLSocket

Google guideline: Caution: SSLSocket does not perform hostname verification. It is up to your app to do its own hostname verification, preferably by calling getDefaultHostnameVerifier() with the expected hostname. Further beware that HostnameVerifier.verify() doesn’t throw an exception on error but instead returns a boolean result that you must explicitly check.

Here is an example showing how you can do this. It shows that when connecting to gmail.com port 443 without SNI support, you’ll receive a certificate for mail.google.com. This is expected in this case, so check to make sure that the certificate is indeed for mail.google.com:

    // Open SSLSocket directly to gmail.com

    SocketFactory sf = SSLSocketFactory.getDefault();

    SSLSocket socket = (SSLSocket) sf.createSocket("gmail.com", 443);

    HostnameVerifier hv = HttpsURLConnection.getDefaultHostnameVerifier();

    SSLSession s = socket.getSession();

    // Verify that the certicate hostname is for
    // mail.google.com. This is due to lack of SNI
    // support in the current SSLSocket.

    if (!hv.verify("mail.google.com", s)) {
        throw new SSLHandshakeException("Expected mail.google.com, found " + s.getPeerPrincipal());

    }

    // At this point SSLSocket performed certificate
    // verification and we have performed hostname verification , so it is safe to proceed.

    // ... use socket ...

    socket.close();

Listing 21. Warnings about using SSLSocket directly

Rule design: The logic of Rule 25 is shown in Algorithm 25. We look for SSLSocket objects in the code of the app. If we find any SSL socket object that does not perform hostname verification, we consider it a violation to the rule.

Algorithm 25: Warnings about using SSLSocket directly

    begin
        sslSessions ← getAllSslSessions()
        verifiers ← getAllHostnameVerifiers()
        foreach ver in verifiers do
            if not verifiesWithAny(ver, sslSessions) then
                Rule 25 is not respected.
            end
        end
    end

Attack: A malicious app can launch a man-in-the-middle attack against an app that does not use HTTPS or SSL at all. Moreover, if the victim app does not verify the certificate sent by a server, the attacker can even pretend to the remote server and establish a communication with the victim app.

## A.26 Rule 26 - Configure CAs for debugging

Google guideline: When debugging an app that connects over HTTPS, you may want to connect to a local development server, which does not have the SSL certificate for your production server. In order to support this without any modification to your app’s code, you can specify debug-only CAs, which are trusted only when android:debuggable is true, by using debug-overrides. Normally, IDEs and build tools set this flag automatically for non-release builds. This is safer than the usual conditional code because, as a security precaution, app stores do not accept apps which are marked debuggable.

res/xml/network_security_config.xml:

    <?xml version ="1.0" encoding ="utf-8" ?>
    <network-security-config>
        <debug-overrides>
            <trust-anchors>
                <certificates src ="@raw/debug_cas"/>
            </trust-anchors>
        </debug-overrides>
    </network-security-config>

Listing 22. Configure CAs for debugging

Rule design: The logic of Rule 26 is shown in Algorithm 26. We look at the manifest of the app. If the app has debugging enabled, and the network configuration defines a debug override, we show a warning.

Algorithm 26: Configure CAs for debugging

    begin
        str ← “networkSecurityConfig”
        element1 ← “<network-security-config>”
        element2 ← “<debug-overrides>”
        app ← getManifestApplicationElement()
        appAttrs ← getAttrs(app);
        if isDebuggableApp() then
            foreach attr in appAttrs do
                if attr = str then
                    confEls ← getNetSecElements()
                    if element1 in confEls then
                        if element2 in confEls then
                            Rule 26 is not respected.
                        end
                    end
                end
            end
        end
    end

Attack: Using conditional code to handle connection to a local development server could lead to mistakes in production builds. If developers forget this conditional code, or this conditional code is not well managed, then an attacker could exploit these mistakes and perform a man-in-the-middle attack.

## A.27 Rule 27 - Do not allow cleartext traffic

Google guideline: Note: the guidance in this section applies only to apps that target Android 8.1 (API level 27) or lower. Starting with Android 9 (API level 28), cleartext support is disabled by default.

Applications intending to connect to destinations using only secure connections can opt-out of supporting cleartext (using the unencrypted HTTP protocol instead of HTTPS) to those destinations. This option helps prevent accidental regressions in apps due to changes in URLs provided by external sources such as backend servers. See NetworkSecurityPolicy.isCleartextTrafficPermitted() for more details.
For example, an app may want to ensure that all connections to secure.example.com are always done over HTTPS to protect sensitive traffic from hostile networks.
res/xml/network_security_config.xml:

    <?xml version ="1.0" encoding ="utf-8" ?>
    <network-security-config>
        <domain-config cleartextTrafficPermitted ="false">
            <domain includeSubdomains ="true">
                secure.example.com
            </domain>
        </domain-config>
    </network-security-config>

Listing 23. Opt out of cleartext traffic

Rule design: The logic of Rule 27 is shown in Algorithm 27. We look at the manifest of the app. If the manifest enables clear-text traffic, we consider it a violation to the rule.

Algorithm 27: Opt out of cleartext traffic

    begin
        s1 ← “networkSecurityConfig”
        s2 ← “cleartextTrafficPermitted”
        elements ← [“<domain-config>”, “<base-config>”]
        app ← getManifestApplicationElement()
        appAttrs ← getAttrs(app);
        foreach attr in appAttrs do
            if attr = s1 then
                confElements ← getNetSecElements()
                foreach element in elements do
                    if element in confElements then
                        dcAttrs ← getAttrs(element)
                        foreach dcAttr in dcAttrs do
                            if dcAttr.name = s2 then
                                if dcAttr.value then
                                    Rule 27 is not respected.
                                end
                            end
                        end
                    end
                end
            end
        end
    end

Attack: With the cleartextTrafficPermitted flag set to true, any connection using HTTP is allowed. Thus, an attacker can eavesdrop the cleartext content of any communication established by the victim app.

## A.28 Rule 28 - Choose a recommended cryptographic algorithm

Google Guideline: When you have the freedom to choose which algorithm to use (such as when you do not require compatibility with a third-party system), we recommend using the following algorithms:

- Cipher class: AES in CBC or GCM mode with 256-bit keys (such as AES/ GCM/ NoPadding)
- MessageDigest class: SHA-2 family (e.g., SHA-256)
- Mac class: SHA-2 family HMAC (e.g., HMACSHA256)
- Signature class: SHA-2 family with ECDSA (e.g., SHA256withECDSA)

Rule design: The logic of Rule 28 is shown in Algorithm 28. We inspect all the invocations to crypto methods, and verify if they are called with insecure arguments.

Attack: If an app does not properly use cryptographic algorithms or it uses insecure ones, a malicious app can break and access to any data or communication, which should have been protected by cryptography.

Algorithm 28: Choose a recommended algorithm

    begin
        cryptoMethods ← getAllCryptoMethods()
        foreach method in cryptoMethods do
            if not usesRecommendedClassArgs(method) then
                Rule 28 is not respected.
            end
        end
    end

## A.29 Rule 29 - Do not use deprecated cryptographic functionality

Google guideline: The following subsections describe deprecated functionality that you should no longer use in your app.

A.29.1 Bouncy Castle algorithms. A number of algorithms from the "Bouncy Castle provider" that are also provided by another provider have been deprecated in Android P. This only affects cases where the implementation from the Bouncy Castle provider is explicitly requested, such as Cipher.getInstance("AES/CBC/PKCS7PADDING", "BC" or Cipher.getInstance("AES/CBC/PKCS7PADDING", Security.getProvider("BC")). Requesting a specific provider is discouraged, so if you follow that guideline this deprecation should not affect you.

A.29.2 Password-based encryption ciphers without an IV. Password-based encryption (PBE) ciphers that require an initialization vector (IV) can obtain it from the key, if it’s suitably constructed, or from an explicitly-passed IV. When passing a PBE key that doesn’t contain an IV and no explicit IV, the PBE ciphers on Android currently assume an IV of zero.
When using PBE ciphers, always pass an explicit IV, as shown in the following code snippet:

    SecretKey key = ...;

    Cipher cipher = Cipher.getInstance("PBEWITHSHA256AND256BITAES-CBC-BC");

    byte[] iv = new byte[16]; 
    new SecureRandom().nextBytes(iv);
    cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

Listing 24. Password-based encryption ciphers without an IV

Rule design: The logic of Rule 29 is shown in Algorithm 29. We look at the code of the app. If the app calls the Cipher.getInstance() method with an explicit provider, or if it uses PBE ciphers without proper initialization, we consider it a violation to the rule.

Attack: When deprecated and insecure cryptographic algorithms are used, a malicious app can decrypt any sensitive data previously encrypted by the legitimate app.

Algorithm 29: Deprecated cryptographic functionality

    begin
        ciphers ← getAllCipherGetInstance()
        foreach cipher in ciphers do
            if hasSecondArgument(cipher) then
                Rule 29 is not respected.
            end
            if hasPBE(cipher) then
                if not hasInit(cipher) then
                    Rule 29 is not respected.
                end
            end
        end
    end

## A.30 Rule 30 - Do not migrate private information to device encrypted storage

Google guideline: If a user updates their device to use Direct Boot mode, you might have existing data that needs to get migrated to device encrypted storage. Use Context.moveSharedPreferencesFrom() and Context.moveDatabaseFrom() to migrate preference and database data between credential encrypted storage and device encrypted storage.

Use your best judgment when deciding what data to migrate from credential encrypted storage to device encrypted storage.

You should not migrate private user information, such as passwords or authorization tokens, to device encrypted storage. In some scenarios, you might need to manage separate sets of data in the two encrypted stores.

Rule design: The logic of Rule 30 is shown in Algorithm 30. If the application tries to migrate data to the device encrypted storage, we show a warning to remind the user that private information, such as passwords or authorization tokens, should not be stored in device encrypted storage.

Algorithm 30: Migrate existing data

    begin
        arr ← [“moveSharedPreferencesFrom”, “moveDatabaseFrom”]
        methods ← getAllCalledMethods()
        foreach method in methods do
            if method in arr then
                Rule 30 is not respected.
            end
        end
    end

Attack: The device encrypted storage is accessible to apps before the user unlocks the screen of the device for the first time after boot. An attacker could exploit this to get access to sensitive information without needing the user to unlock the device.

## A.31 Rule 31 - Use device encrypted storage for Direct Boot only

Google guideline: Use device encrypted storage only for information that must be accessible during Direct Boot mode. Do not use device encrypted storage as a general-purpose encrypted store.

Rule design: The logic of Rule 31 is shown in Algorithm 31. If the application tries to access the device encrypted storage, we show a warning to remind that device encrypted storage should only be used for data that needs to be accessed before the user unlocks the device for the first time.


Algorithm 31: Access device encrypted storage

    begin
        methods ← getAllCalledMethods()
        str ← “createDeviceProtectedStorageContext”
            foreach method in methods do
                if method = str then
                    Rule 31 is not respected.
                end
            end
    end

Attack: The device encrypted storage is accessible to apps before the user unlocks the screen of the device for the first time. An attacker could exploit this to get access to sensitive information without needing the user to unlock the device after boot.