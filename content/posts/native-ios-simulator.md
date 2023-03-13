+++
title = "Natively using a library meant for the iOS simulator"
date = 2020-12-24
+++

Like any mischevious reverse engineer + music lover, I wanted to find a way to download songs from Spotify. (Surprise! Another Spotify post!). I eventually found a way to do this using the Spotify iOS SDK. I'm pretty sure I legally can't say exactly how (fuck the DMCA or whichever law it is) but it works by 1) linking the iOS SDK to an app in Xcode, 2) running that app in the x86 iOS simulator, and 3) selecting a song to play while simulateously saving it to a file. 

This all works fine (if not a little clunky) but who wants to run the iOS simulator to download a song to their MacBook? (Also no one would want to download a song this way. One, it's illegal and wrong to the artist and to Spotify. Two, you have to have Spotify Premium for it to work so there's no financial motivation for it (except in distribution). I don't even use it, I just like to say I can do it).

But anyways, from a code/concept cleanliness standpoint, I wanted to get this to run as a native Mac app. Now this doesn't *sound* too hard but if you try to link the Spotify iOS SDK (framework) to a Mac app in Xcode, you'll get the following build error:

```
Building for macOS, but the linked and embedded framework 'SpotifyAudioPlayback.framework' was built for iOS + iOS Simulator.
```

Somehow Xcode knows what platform the framewokrk was built for. I figured that the information necessary to perform this check was stored in the `Info.plist` as I'm not aware of any fields in the Mach-O header that specify the platform.

I tried changing the `CFBundleSupportedPlatforms` key from `iphoneOS` to `macOS`, updating the `MinimumOSVersion` key, and deleting the `DTPlatformName`, `DTPlatformVersion`, `DTSDKName`, and `UIDeviceFamily` keys. Interestingly enough Xcode now threw the error:

```
Building for macOS, but the linked and embedded framework 'SpotifyAudioPlayback.framework' was built for iOS Simulator.
```

Xcode no longers thinks that the framework was built for just the `iOS` platform. Progress?

Anyways, then I thought that maybe Xcode had cached the platform information from a previous build and wasn't event looking at most of the updated plist. So after some fiddling, I changed the `CFBundleIdentifier`, `CFBundleName`, and `CFBundleExecutable` keys (changing the name of the binary accordingly). 

Lo and behold, it works! We can now build our Mac app with the Spotify iOS SDK linked. Well... actually not. Xcode no longer complains about the framework's platform, but we now get three brand-spankin-new build errors:

```
Undefined symbol: _OBJC_CLASS_$_UIApplication
Undefined symbol: _OBJC_CLASS_$_UIDevice
Undefined symbol: _UIBackgroundTaskInvalid
```

These errors make sense. The iOS code expects to have UIKit but we don't have UIKit on Mac. I'm  surprised that these are the only symbols the SDK needs from UIKit.

Nevertheless, there's no reason to fret. All we have to do is implement our own `UIApplication` and `UIDevice` classes as well as the `UIBackgroundTaskInvalid` constant. We only need to implement the functionality that the SDK uses so hopefully it's not complex.

Let's start with `UIBackgroundTaskInvalid`. I'm sure there's an easier way to do this but I just ran an iOS app in the simulator, printing out the value of the constant (`UIBackgroundTaskInvalid` has type `UIBackgroundTaskIdentifier` which is just an alias for an unsigned long). This value turns out to be zero. So let's just add

```
NSUInteger UIBackgroundTaskInvalid = 0;
```

Boom. Done. Recompile and now we've only got two errors. Too easy.

Now let's look at how the SDK uses `UIApplication`. In Ghidra, we can see that the singleton `UIApplication.sharedApplication` is only used once:

![uiapp_usage](/uiapp_usage.png)

It looks like if the shared `UIApplication` is non-null (which I suspect would always be the case when running in iOS), the code starts a `UIBackgroundTask` so that it can continue playing music even when the app using the SDK isn't in the foreground. Cool! We don't care about that! We can just return null for `UIApplication.sharedApplication` and go on our merry way:

```
@implementation UIApplication

+ (id)sharedApplication {
    return NULL;
}

@end
```

Finally, let's take a look at `UIDevice`:

![uidev_use1](/uidev_use1.png)

![uidev_use2](/uidev_use2.png)

The `UIDevice.currentDevice` singleton is used twice. Once to retrieve the `systemVersion` property (of type `NSString`) and once to retrieve the `identifierForVersion` property which as type `NSUUID`.

The SDK does no validation on these properties so we can simply make them up!

```
@implementation UIDevice

@synthesize systemVersion;
@synthesize identifierForVendor;

+ (id)currentDevice {
    // Singleton code shamelessly stolen from somewhere. Probably SO.
    static UIDevice *shared = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[self alloc] init];
    });
    return shared;
}

- (id)init {
    if (self = [super init]) {
        systemVersion = @"1.3.3.7";
        identifierForVendor = [[NSUUID alloc] init];
    }
    return self;
}
@end
```

And voila! Build errors begone. We can now use the Spotify iOS SDK to play Spotify songs on macOS. Pretty cool. Keep in mind that I just linked/used the `SpotifyAudioPlayback` framework, not the `SpotifyAuthentication` or `SpotifyMetadata` frameworks (I'm using [SpotifyKit](https://github.com/xzzz9097/SpotifyKit) for OAuth. Why? I don't really know). There might be other functionality that needs to be implemented for these frameworks.

I'm honestly surprised that all of the CoreAudio stuff that the SDK uses works out of the box on Mac. I wouldn't be surprised if this breaks under certain conditions but hey, good enough for a PoC.

I hope you enjoyed and as always let me know if I got something wrong. Also please don't sue me.
