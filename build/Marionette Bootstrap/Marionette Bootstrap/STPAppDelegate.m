//
//  STPAppDelegate.m
//  Marionette Bootstrap
//
//  Created by Andreas Fuchs on 5/1/14.
//  Copyright (c) 2014 Stripe. All rights reserved.
//

#import "STPAppDelegate.h"

@implementation STPAppDelegate

OSStatus DoTerminalScript(const char *utf8Script) {
  /*
   * Run a shell script in Terminal.app.
   * (Terminal.app must be running first.)
   */
  char *bundleID = "com.apple.terminal";
  AppleEvent evt, res;
  AEDesc desc;
  OSStatus err;
  
  // Build event
  err = AEBuildAppleEvent(kAECoreSuite, kAEDoScript,
                          typeApplicationBundleID,
                          bundleID, strlen(bundleID),
                          kAutoGenerateReturnID,
                          kAnyTransactionID,
                          &evt, NULL,
                          "'----':utf8(@)", strlen(utf8Script),
                          utf8Script);
  if (err) return err;
  // Send event and check for any Apple Event Manager errors
  err = AESendMessage(&evt, &res, kAEWaitReply, kAEDefaultTimeout);
  AEDisposeDesc(&evt);
  if (err) return err;
  // Check for any application errors
  err = AEGetParamDesc(&res, keyErrorNumber, typeSInt32, &desc);
  AEDisposeDesc(&res);
  if (!err) {
    AEGetDescData(&desc, &err, sizeof(err));
    AEDisposeDesc(&desc);
  } else if (err == errAEDescNotFound)
    err = noErr;
  return err;
}

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification
{
  // TODO: This is an utter jankfest. (Mostly because we have to chdir to the directory, boo).
  // However,
  if([[NSWorkspace sharedWorkspace] launchApplication:@"Terminal"]) {
    NSString *path = [[NSBundle mainBundle] pathForResource:@"bootstrap" ofType:nil];
    path = [@"'" stringByAppendingString:[path stringByAppendingString:@"' && exit"]];
    NSLog(@"Running script %@", path);
    DoTerminalScript([path UTF8String]);
  }
}

@end
