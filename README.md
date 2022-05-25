Some Techniques to Detect Frida

Inspiration Taken From
https://sysfatal.github.io/bypassfrida-en.html

1. Detection Based On Instruction Change

When we intercept any function or exported method with help of frida , it introduces own trampoline
to able to intercept that target function . 

we can see this with a example

```sh
var Addr = Module.findExportByName("libc.so","open");
Ins(Addr,3);
function Ins(nativePtr, instructionCount) {
    var instructionArr = [];
    for (var i = 0; i < instructionCount; i++) {
        var dissAsm = Instruction.parse(nativePtr);
        console.log(dissAsm);
        nativePtr = dissAsm.next;
    }        
}
```
what we are doing is parsing few instructions of libc method named open
and printing them. 

and we got output as

```sh
sub sp, sp, #0x130
stp x29, x30, [sp, #0xe0]
str x28, [sp, #0xf0]
```

Now we going to use frida's Interceptor.attach on open method along with printing instruction.
To see if frida is really changing instructions. 
after adding Interceptor.attach

```sh
var Addr = Module.findExportByName("libc.so","open");
function Ins(nativePtr, instructionCount) {
    var instructionArr = [];
    for (var i = 0; i < instructionCount; i++) {
        var dissAsm = Instruction.parse(nativePtr);
        console.log(dissAsm);
        nativePtr = dissAsm.next;
    }        
}
Interceptor.attach(Module.findExportByName("libc.so","open"), function (args) {
          console.warn(args[0].readCString());
})

Ins(Addr,3);
```

some of you might ask that - why printing instructions after Interceptor.attach code because order of code really matter while testing on same script , if you don't believe
you can try printing address on top of script and it will give same instructions ( why because we testing same code with frida , it is not inbuilt into app yet , so frida correctly parse thing) . untill these code are
not pushed into app . 

so output of script is -

```sh
sub sp, sp, #0x130
br x16
adrp x0, #0x7a6a570000
```

which is definitely not equals to what we seen at first try . so 2 instructions changed by frida for its own trampoline .

we can repeat same for other libc method to confirm. 
lets try on stat , access and syscall.

For stat 
before Interceptor.attach
```sh
mov x8, x0
mov x2, x1
mov w0, #-0x64
```
after Interceptor.attach

```sh
mov x8, x0
br x16
adrp x0, #0x7a6a574000
```

For Access
before Interceptor.attach
```sh
mov x8, x0
mov w2, w1
mov w0, #-0x64
```
after Interceptor.attach

```sh
mov x8, x0
br x16
adrp x0, #0x7a36565000
```

For Syscall
before Interceptor.attach
```sh
mov x8, x0
mov x0, x1
mov x1, x2
```
after Interceptor.attach
```sh
mov x8, x0
br x16
adrp x0, #0x7b12762000
```

if we feed these instructions into app and test frida on it then it will do the work.

and a PoC app is available at 
https://github.com/apkunpacker/Frida-Detection/blob/main/Hook%20Detect.apk

with code ( tested was on armv7 version of gadget so libc instruction are also according to that , you guys can repeat for arm64 like above)

when code is used inside as a app , frida change instructions from 1st place 

```sh
var open = Module.findExportByName("libc.so", 'open');
var access = Module.findExportByName("libc.so", 'access');
var stat = Module.findExportByName("libc.so", 'stat');
var syscall = Module.findExportByName("libc.so", 'syscall');
var O = Instruction.parse(open);
var A = Instruction.parse(access);
var S = Instruction.parse(stat)
var SC = Instruction.parse(syscall);
if(O.toString().indexOf("sub sp")<0) {
  hook("Detected Hook On Libc.so Open");
}
if(A.toString().indexOf("mov r2")<0) {
  hook("Detected Hook On Libc.so Access");
}
if(S.toString().indexOf("mov r2")<0) {
  hook("Detected Hook On Libc.so Stat");
}
if(SC.toString().indexOf("mov ip")<0) {
  hook("Detected Hook On Libc.so Syscall");
}
function hook(input) {
    if (Java.available) {
    Java.perform(function() {
        var context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
        Java.scheduleOnMainThread(function() {
            var toast = Java.use("android.widget.Toast");
            toast.makeText(Java.use("android.app.ActivityThread").currentApplication().getApplicationContext(), Java.use("java.lang.String").$new(input), 1).show();
        });
    });                        
  }
}
```
![158595324-a3d0e31f-5a0d-41ff-8286-963c0af610f7](https://user-images.githubusercontent.com/27184655/170197700-4b285080-6c95-4681-b271-cb7e5fb1be6e.jpg)
