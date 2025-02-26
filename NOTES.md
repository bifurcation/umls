# Minimizing memory usage

## Emprical

Using GDB:
https://interrupt.memfault.com/blog/measuring-stack-usage
https://nusgreyhats.org/posts/writeups/basic-lldb-scripting/

Using `-Z emit-stack-sizes`:
https://doc.rust-lang.org/beta/unstable-book/compiler-flags/emit-stack-sizes.html

Using stack painting:
...


## Theoretical

There are two things that are expensive:

* Joining the group
* Sending a commit

And we should keep in mind that the inputs / outputs are immediately bound
to/from serial data.  So there are advantages to working in serialized form


### Join group

* In: KeyPackagePriv, Welcome
* Out: RatchetTree, GroupState

Potential memory layout:

```
 Input: |<-KPP->|<--------------Welcome-------------->|
Output:                  |<--------RatchetTree------->|<-GS->|  
```

Requires:
* Mutable parse => in-place decrypt without taking ownership
* Lazy parse => Don't materialize the tree in memory

Serialize @128
KeyPackagePriv     99
Welcome         82000
GroupState      82120
                =====
               164219

Inline
KeyPackagePriv     99
Welcome         82000
GroupState        555
                =====
                82654


### Send Commit

* In: GroupState, Ops, RatchetTree
* Out: GroupState, Commit, Welcome

Serialized @128
GroupState      82120
  RatchetTree   81565
Commit          61355
Welcome         82000

Split GroupState from RatchetTree
GroupState        555
RatchetTree     81565
Commit          61355
Welcome         82000

AES-CM on RatchetTree => take it out of GroupInfo
GroupState        555
RatchetTree     81565
Commit          61355
Welcome           435
                =====
               143900
