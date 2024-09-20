package com.android.hp;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;
import android.widget.Toast;

import dalvik.system.BaseDexClassLoader;

import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodHook.Unhook;
import de.robv.android.xposed.XC_MethodHook.MethodHookParam;

import java.io.File;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Entry {

    private static final String TAG = "Entry-demo";

    public static void init(Context appContext, Bundle params) {
        String pkgName = appContext.getPackageName();
        ClassLoader cl = appContext.getClassLoader();
        ClassLoader sys_cl = ClassLoader.getSystemClassLoader();
        Log.d(TAG, "loader " + pkgName + " " + appContext);
        Log.d(TAG, "app cl " + cl);
        Log.d(TAG, "sys cl " + sys_cl);
        Log.d(TAG, "XposedBridge cl " + XposedBridge.class.getClassLoader());

        try {
            Log.d(TAG, "loadLibrary libpg start");
            System.loadLibrary("pg");
            Log.d(TAG, "loadLibrary libpg success");
            initNative(0);
        } catch (Exception e) {
            Log.w(TAG, "Failed load" , e);
        }

        if (pkgName.equals("com.godevelopers.XposedChecker")) {
            hookXposedDetecte(appContext, cl);
        } else if (pkgName.contains("com.finalwire.aida64")) {
            testAida64(cl);
        }

        //File dir = appContext.getDir("cache", Context.MODE_PRIVATE);
        //addDexPath(cl, "/data/local/tmp/lspd.dex", dir);
    }

    public static void testAida64(ClassLoader cl){     
        try {
            XposedBridge.log("hello xposed!");

            XC_MethodHook.Unhook hookd = null;
            XC_MethodHook cb = null;

            cb = new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    super.beforeHookedMethod(param);
                    Log.d(TAG, "HHMainActivity onCreate beforeHookedMethod");
                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                    Log.d(TAG, "HHMainActivity onCreate afterHookedMethod");
                }
            };

            hookd = XposedHelpers.findAndHookMethod("com.finalwire.aida64.HHMainActivity", cl, "onCreate",
                    android.os.Bundle.class, cb);

            Log.d(TAG, "init done " + hookd);
        } catch (Exception e) {
            Log.d(TAG, "init fail", e);
        }
        
    }

    public static void addDexPath(ClassLoader cl, String dexPath, File dir) {
        try {
            Field pathListField = BaseDexClassLoader.class.getDeclaredField("pathList");
            pathListField.setAccessible(true);
            Object pathList = pathListField.get(cl);
            if (pathList == null) {
                Log.d(TAG, "addDexPath pathlist is null");
                return;
            }
            Method addDexPath = pathList.getClass().getDeclaredMethod("addDexPath",new Class[]{String.class, File.class});
            addDexPath.invoke(pathList, dexPath, dir);
            Log.d(TAG, "addDexPath" + dexPath + " to " + cl);
        } catch (Exception e){
            Log.e(TAG, "addDexPath",  e);
        }
    }


    public static void hookXposedDetecte(Context appContext, ClassLoader classLoader) {
        try {
            XposedHelpers.findAndHookMethod("com.godevelopers.checker.check$1", classLoader, "onClick", android.view.View.class, new XC_MethodHook() {
                @Override
                protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                    Toast.makeText(appContext, "Alread Hooked", Toast.LENGTH_LONG).show();
                    super.beforeHookedMethod(param);
                }
                @Override
                protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                    super.afterHookedMethod(param);
                }
            });
        } catch (Exception e) {
            Log.w(TAG, "hook hookXposedDetecte failed", e);
        }
    }

    private static native boolean initNative(int flags);

    private static native boolean deInitNative(int flags);
}
