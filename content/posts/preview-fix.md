+++
title = "Fixing Other Peoples Software: Preview.app"
date = 2025-11-06
+++

## Introduction
Every now and then I find myself having to author a LaTeX document.
Aside from the usual frustrations that come with writing LaTeX, I've come across a feature in Preview on MacOS that really bugs me.

See, my LaTeX workflow is to have two windows side-by-side in full screen mode.
On the left, I write the document in vim and manually compile it using `pdflatex` or `xelatex`.
On the right, I have Preview open to look at the compiled PDF.

Preview has a nice feature where it will update the display when the PDF I'm looking at changes (like when I recompile the tex).
The bad part about this feature is that every time it updates, it opens the sidebar and resets the zoom.

<p float="middle" with="100%">
  <img src="/orig_tex.png" alt="Original Display" width="42%" style="margin-left: 3%; margin-right: 3%" />
  <img src="/post_tex.png" alt="Updated Display" width="42%" style="margin-left: 3%; margin-right: 3%" /> 
</p>

Furthermore, the only way I've found to hide the sidebar is to toggle the "Always Show Sidebar" option twice.

This annoys me so much that at one point I started using my web browser as my PDF viewer.
The only problem with this was that it wouldn't auto-update on recompiling so I would have to manually refresh the page.

Eventually, I decided that, hey, I can use [frida](https://frida.re/), let's see if I can quickly fix this issue.

### Sidebar
The first, and more annoying, issue that I'll tackle is the sidebar opening.

To start, I figured I'd just see what sidebar-related functions, if any, are being called when the view updates.
Being a MacOS application and written more than five years ago, I figured there's a good chance it was written at least partially in Objective-C
so I ran the following command:

`frida-trace -p <PID of Preview> -m "-[* *Sidebar:*]" | tee log.txt`

This tells `frida-trace` to log whenever a method on any class containing the substring "Sidebar" is called.

Looking through the log, one method stands out:

```
 13838 ms  -[PVFullScreenController setAutohidesSidebar:0x1]
```

Seems promising.
Just logging this method and manually unchecking and checking the "Always Show Sidebar" option gives the following:

```
  3813 ms  -[PVFullScreenController setAutohidesSidebar:0x0]
  6365 ms  -[PVFullScreenController setAutohidesSidebar:0x1]
```

Let's try stubbing out this function to see if it disables the sidebar.

To do so, we can create the following frida script:

```javascript
var cls = ObjC.classes['PVFullScreenController'];
var meth = cls.instanceMethodForSelector_(ObjC.selector('setAutohidesSidebar:'))

var newImp = new NativeCallback(function (self, _cmd, autohides) {
    console.log('Stubbing -[PVFullScreenController setAutohidesSidebar:' + autohides + ']');
    return;
}, 'void', ['pointer', 'pointer', 'char']);

Interceptor.replace(meth, newImp);
```

Where we could infer the method signature but confirmed it using `otool -ov <path to Preview>` and seeing that the `setAutohidesSidebar` method doesn't return anything and takes a char (boolean):

```
    ...
    name    0x1001c57ab setAutohidesSidebarInFullscreen:
    types   0x1001d797c v20@0:8c16
    ...
```

Unpacking this type signature:

```
    v  -- Method returns void (nothing).
    20 -- Parameters take 20 bytes in total.
    @  -- The first parameter is a pointer to an Objective-C object.
    0  -- The first parameter is at offset 0.
    :  -- The second parameter is an Objective-C selector.
    8  -- This parameter is at offset 8.
    c  -- The third parameter is a char.
    16 -- It's at offset 16.
```

Running this and manually toggling "Always Show Sidebar" doesn't show the sidebar so the script correctly stubbed the functionality:

```
Stubbing -[PVFullScreenController setAutohidesSidebar:0]
Stubbing -[PVFullScreenController setAutohidesSidebar:0]
```

Note that both times the `autohides` parameter is 0 since the first time it was called, we stubbed it out and didn't update its internal state (most likely).

This seems like a win but re-compiling the PDF, we see the method called with the `TRUE` parameter and the sidebar appears:

```
Stubbing -[PVFullScreenController setAutohidesSidebar:1]
Stubbing -[PVFullScreenController setAutohidesSidebar:1]
```

Therefore, the code that actually opens the sidebar must be handled in a different branch of the call tree.
To figure out where the sidebar is actually opened, let's print out the stack trace every time the method is called:

```javascript
// within the NativeCallback...
console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
    .map(DebugSymbol.fromAddress).join('\n') + '\n');
```

We can see that

```
// On manually toggle.
Stubbing -[PVFullScreenController setAutohidesSidebar:0]
0x10c3c19db /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVWindowController toggleAutohidesSidebar:]
0x10c3c4429 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVWindowController toggleHideSidebar:]
0x7ff8130a808e AppKit!-[NSApplication(NSResponder) sendAction:to:from:]
0x7ff81319cc10 AppKit!-[NSMenuItem _corePerformAction]
...

// On auto update.
Stubbing -[PVFullScreenController setAutohidesSidebar:1]
0x10c47a1c3 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVWindowController syncViewStateFromMediaContainer:includingLocation:]
0x10c3a3175 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVWindowController observeValueForKeyPath:ofObject:change:context:]
0x7ff81129816a Foundation!NSKeyValueNotifyObserver
0x7ff81135c069 Foundation!NSKeyValueDidChange
0x7ff81128ac8e Foundation!-[NSObject(NSKeyValueObservingPrivate) _changeValueForKeys:count:maybeOldValuesDict:maybeNewValuesDict:usingBlock:]
0x7ff8112b6122 Foundation!-[NSObject(NSKeyValueObservingPrivate) _changeValueForKey:key:key:usingBlock:]
0x7ff8112b87b7 Foundation!_NSSetCharValueAndNotify
0x10c39c411 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVPDFPageContainer validateSource:]
0x10c39a3ab /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVPDFPageContainer readFromURL:ofType:error:]
0x7ff8133c7c7b AppKit!-[NSDocument revertToContentsOfURL:ofType:error:]
0x10c400fe4 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVMediaContainerBase revertToContentsOfURL:ofType:error:]
...

// On auto update.
Stubbing -[PVFullScreenController setAutohidesSidebar:1]
0x10c47a1c3 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVWindowController syncViewStateFromMediaContainer:includingLocation:]
0x10c3b05d2 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVWindowController didRevertContainer:]
0x10c401089 /System/Applications/Preview.app/Contents/MacOS/Preview!-[PVMediaContainerBase revertToContentsOfURL:ofType:error:]
...
```

I didn't see what looked like the function call in the `syncViewState...` method but after some digging I found the selector
`openSidebarWithAnimation:completionHandler:` which is called from the method `-[PVWindowController _setupUtilityView]`:

```Objective-C
int64_t -[PVWindowController _setupUtilityView]
  ...
  if (rax == 5 || rax == 6 || rax == 7)
  {
      ...
      rax_12 = &openSidebarSelector
  }
  ...
  if (rax == 7 || rax == 5 || rax == 6 || rax u> 8 || rax == 0 || rax == 8)
  {
      _objc_msgSend(rbx, *rax_12)
      ...
  }
```

which is in turn called from `-[PVWindowController didRevertContainer:]`:

```Objective-C
int64_t didRevertContainer(void* arg1, int64_t arg2, int64_t arg3)
    int64_t rax = _objc_retain(arg3)
    int64_t rax_2 = _objc_retainAutoreleasedReturnValue(_objc_msgSend(arg1, "currentMediaContainer"))
    _objc_release(rax_2)
    if (rax_2 == rax)
    {
        _objc_msgSend(arg1, "initializeViewStateOnMediaContai…")
        _objc_msgSend(arg1, "syncViewStateFromMediaContainer:…")
        *(arg1 + data_100268ab0) = 0
    }
    _objc_msgSend(rax, "setHasNeverBeenEdited:")
    _objc_msgSend(arg1, "_setupUtilityView")
    _objc_msgSend(arg1, "updateCurrentPageNumberUI")
    _objc_msgSend(*(arg1 + data_100268b10), "setNeedsDisplay:")
    return _objc_release(rax) __tailcall
```

Stubbing the `openSidebar...` method finally correctly disables the sidebar.

To make this even better, we can stub only calls to `openSidebar...` from `_setupUtilityView` so that if we want, we can manually show the sidebar.
Here is the final frida script for the sidebar:

```javascript
var cls = ObjC.classes['PVWindowController'];
var meth = cls.instanceMethodForSelector_(ObjC.selector('openSidebarWithAnimation:completionHandler:'))
var orig = new NativeFunction(meth, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

var newImpl = new NativeCallback(function (self, _cmd, animation, callback) {
    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
    var callingFunc = '' + DebugSymbol.fromAddress(bt[0]);

    if (callingFunc.indexOf('-[PVWindowController _setupUtilityView]') >= 0) {
        console.log('Stubbing showSidebar');
        return;
    } else {
        orig(self, _cmd, animation, callback);
        return;
    }
}, 'void', ['pointer', 'pointer', 'pointer', 'pointer']);

Interceptor.replace(meth, newImpl);
```

### Zoom
Looking at the decompilation for the `syncViewState...` method, we see some interesting-looking method calls:

```Objective-C
    ...
            if (arg4.b != 0)
            {
                zmm0_6 = _objc_msgSend(rax, "zoomCenter")
                zmm0_6 - 9.2233720368547758e+18
                if (zmm0_6 != 9.2233720368547758e+18 || (not(zmm0_6 != 9.2233720368547758e+18) && not(is_ordered.q(zmm0_6, 9.2233720368547758e+18))))
                {
                    _objc_msgSend(rax, "uiZoomFactor")
                    r12_3 = var_50_1
                    var_40_1.q = _objc_msgSend(r12_3, "zoomFactorForUIZoomFactor:")
                    _objc_msgSend(rax, "zoomCenter")
                    _objc_msgSend(r12_3, "setZoomFactor:withCenter:animate…")
                }
            }
            if (arg4.b == 0 || (arg4.b != 0 && not(zmm0_6 != 9.2233720368547758e+18) && is_ordered.q(zmm0_6, 9.2233720368547758e+18)))
            {
                _objc_msgSend(rax, "uiZoomFactor")
                r12_3 = var_50_1
                _objc_msgSend(r12_3, "zoomFactorForUIZoomFactor:")
                _objc_msgSend(r12_3, "setZoomFactor:animate:stickyFit:")
            }
    ...
```

Specifically these `setZoomFactor...` methods seem like good candidates for setting the zoom since... yknow... it's in the name.

Checking with `frida-trace` to see if these methods are called, we see that `setZoomFactor:withCenter...` is the one that's called.
Therefore, we can create the following frida hook to stub out the zooming functionality in the correct context:

```javascript
var cls = ObjC.classes['PVPDFView'];
var meth = cls.instanceMethodForSelector_(ObjC.selector('setZoomFactor:withCenter:animate:stickyFit:completion:'))
var orig = new NativeFunction(meth, 'void', ['pointer', 'pointer', 'double', 'double', 'double', 'char', 'char', 'pointer']);

var newImpl = new NativeCallback(function (self, _cmd, factor, x, y, animate, sticky, completion) {
    var bt = Thread.backtrace(this.context, Backtracer.ACCURATE);
    var callingFunc = '' + DebugSymbol.fromAddress(bt[0]);

    if (callingFunc.indexOf('-[PVWindowController syncViewStateFromMediaContainer:includingLocation:]') >= 0) {
        console.log('Stubbing setZoom');
        return;
    } else {
        orig(self, _cmd, factor, x, y, animate, sticky, completion);
        return;
    }
}, 'void', ['pointer', 'pointer', 'double', 'double', 'double', 'char', 'char', 'pointer']);

Interceptor.replace(meth, newImpl);
```

## Conclusion
There's still a slight annoyance that on auto-update the scroll offset is reset to (0, 0) within the current page but this really doesn't annoy me too much.

Anyways, I hope this shows how you too can fix annoyances or bugs in software by using frida and maybe a decompiler.
