---
layout: post
title:  "Persistent Binary Patches"
date:   2020-12-24 12:30:10 -0500
categories: jekyll update
---

As I'm sure you're following this and my [other blog](https://lerner98.medium.com) closely, you'll recall that I have been tracking the songs I skip in Spotify in order to eventually build a model for "flow-state" listening. In order to track my skips, I inject a library into the Spotify binary that hooks the appropriate functions and logs calls to them.

As I'm sure you'll also remember, in [this post](https://saml98.github.io/jekyll/update/2020/05/03/ghidra-stack-strings.html) I encountered a situation where Spotify was auto-updating itself. Hence, a new, unblemished binary would be downloaded and replace the old, infected version. In this post, I'll describe what I've learned about the auto-update process (which isn't much) and how to modify our library to reinject itself into the update binary.

## Searching for the Update

Let's think about some possible ways an app could implement an auto-update feature.

One way could be to:

```
1. Download the update (either to a tmp file or to the same path as the currently executing binary).
2. Move the update file to overwrite the existing file (if not overwritten on download).
3. Wait until the application is exited/relaunched to run the updated version.
```

or

```
1. Download the update.
2. Replace the existing version.
3. Run `exec` to run the upgrade immediately.
```

In both scenarios, steps (1) and (2) are the same, but in scenario 2, we have to infect the update before step (3). This is because, if we wait for the current process memory to be replaced with the update's, our injection code will be overwritten as well. In scenario 1, we don't have this constraint; all we need to do is infect the update sometime before the current application exits.

To insure ourselves againt both scenarios, we'll reinfect the update before step (3) and preferably before step (2) (you'll see why later).

### Finding the Function

We know that to perform step (2), we'll most likely need to overwrite `/Applications/Spotify.app/Contents` since that's where the current binary lives. Searching for that string and variants, we come across the following code (note all code snippets are cleaned-up Ghidra output):

```
void FUN_1008c8a30(void * param_1, void * param_2, long param_3, long param_4)
{
    ...
    char * c_str = param_2 + 1;

    if ((*param_2 & 1) != 0)
        c_str = *(param_2 + 0x10);

    NSString * str1 = [NSString stringWithUTF8String:c_str];
    NSString * str2 = [str1 stringByAppendingFormat:"/%s.app", "Spotify"];
    ...
}
```

My guess is that `param_2` is a C++ string with a structure similar to:

```
struct str_ptr {
    ... 15 unknown bytes ...
    char * ptr;
}

struct str {
    // 0 - The string is small and therefore stored in `data.s`.
    // 1 - The string is large and therefore pointed to by `data.sp.ptr`.
    byte flags;

    union {
        char s[sizeof(struct str_ptr)];
        struct str_ptr sp;
    } data;
}
```

Regardless, this function looks like it a promising place to start looking.

Looking at some more log messages in the function, we see that this function originated from a file called `background_update_extractor.mm`:

![log](/images/update_log.png)

Very promising indeed.

Let's look at more of the function's code to see what it does:

```
{
    ...
    NSTask * task = [[NSTask alloc] init];
    task.launchPath = @"/usr/bin/tar";

    c_str = param_1->data.s1;

    if ((param_1->flags & 1) != 0)
        c_str = *(param_1->data.sp.ptr);

    NSString * str3 = [NSString stringWithUTF8String:c_str];
    task.arguments = @[@"xf", str3];

    task.currentDirectoryPath = str2;

    [task launch];
    [task waitUntilExit];
    ...
}
```

Things should hopefully be starting to come together.

It appears that the update is downloaded as a tarball to `param_1` and is unpacked to `<param_2>/Spotify.app`. To confirm this, we can set a breakpoint at this function and print the two parameters (note that we have to wait for an auto-update to be available for this function to be called so patience is recommended for this step!):

![params](/images/log_params.png)

We can confirm that the ".tbz" file is a compressed (bzip2) tarball and once the `NSTask` completes, the "sp_update" tmp folder will have a fresh copy of "Spotify.app" in it.

All we need to do now if find an appropriate method to hook (after the call to `[task launch]`.

### Finding Method Calls

We want our hooked method to satisfy a few conditions:

```
1. It's only called after `[task launch]`.
2. It's called 100% of the time.
3. It's called as close to `[task launch]` as possible but not before.
```

Looking at calls that are executed directly after `[task launch]`, the most obvious choice is the call to `[task waitUntilExit]` directly after it. All we have to do now is confirm that it's only called at the right time. We want this condition so that our hook doesn't get triggered randomly and we try to infect a non-existing update.

One thing we can do scour the binary and check that `[task waitUntilExit]` is only called once. However, a simpler thing we can do is to check that `NSTask * self` has the arguments we expect in our hook.

Therefore, the beginning of our hook will look like this:

```
void my_waitUntilExit(NSTask * self, SEL cmd)
{
    // Call the original method.
    ((proto_waitUntilExit *)orig_waitUntilExit)(self, cmd);

    NSString * exec = self.launchPath,
             * cwd = self.currentDirectoryPath;
    NSArray * args = self.arguments;

    if ((exec && cwd && args && \
         [exec isEqualTo:@"/usr/bin/tar"] && \
         [cwd hasSuffix:@"Spotify.app"] && \
         args.count > 0 && \
         [args[0] isEqualTo:@"xf"]))
    {
        ...
    }
}
```

So we check that if we were running our command in a shell, it would look like this:

```
Spotify.app> /usr/bin/tar xf <BZIP PATH>
```

### The Rest of the Hook

Then in the if statement, we need to

```
1. Parse the dylibs current loaded from /Applications/Spotify.app/Contents/MacOS/Spotify
2. Reinject any dylibs prefixed with "spskip" into <UPDATE PATH>/Spotify.app/Contents/MacOS/Spotify
3. Change the "maxprot" of the "__TEXT" section to RXW so that we can monkey-patch the binary in the tracer library.
    (Read the automatic hook resolution post for why we need to write code at runtime).
```

As a test, we can prepare a tarball of a directory with `/Contents/MacOS/Spotify` contents and write a small test program like so:

```
NSTask * task = [[NSTask alloc] init];

task.launchPath = @"/usr/bin/tar";
task.arguments = @[@"xf", TARBALL];
task.currentDirectoryPath = UPDATE_DIR;

[task launch];
[task waitUntilExit];
```

Then we can run `otool -L Spotify.app/Contents/MacOS/Spotify` and see that the appropriate libraries were reinjected:

```
Spotify.app/Contents/MacOS/Spotify:
    ...
	/Users/samlerner/Projects/SPSkip/MacOS/LibSkipMac/spskip_tracer.dylib (compatibility version 0.0.0, current version 0.0.0)
	/Users/samlerner/Projects/SPSkip/MacOS/reinjector/spskip_reinjector.dylib (compatibility version 0.0.0, current version 0.0.0)
```

And we can run `objdump --private-headers Spotify.app/Contents/MacOS/Spotify` to see that `__TEXT.maxprot` has been appropriately set:

```
Load command 1
      cmd LC_SEGMENT_64
  cmdsize 1112
  segname __TEXT
   vmaddr 0x0000000100000000
   vmsize 0x0000000001af8000
  fileoff 0
 filesize 28278784
  maxprot rwx
 initprot r-x
   nsects 13
    flags (none)
```

## Conclusion

Well that's a wrap. I hope you you learned something that you might be able to take away to other reversing tasks. You might also learn something about Mach-O parsing and/or the Objective-C runtime if you take a look at the [code](https://github.com/SamL98/SPSkip/tree/master/MacOS/reinjector).

Let me know if you have any comments on [twitter](https://twitter.com/samnlerner) or email.
