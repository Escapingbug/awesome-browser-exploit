# awesome-browser-exploit
Share some useful archives about browser exploitation.

I'm just starting to collect what I can found, and I'm only a starter in this area
as well. Contributions are welcome.

# Chrome v8
## Basic
* [v8 github mirror(docs within)](https://github.com/v8/v8)[github]
* [on-stack replacement in v8](http://wingolog.org/archives/2011/06/20/on-stack-replacement-in-v8)[article] // multiple articles can be found within
* [A tour of V8: Garbage Collection](http://www.jayconrod.com/posts/55/a-tour-of-v8-garbage-collection)[article]
* [A tour of V8: object representation](http://www.jayconrod.com/posts/52/a-tour-of-v8-object-representation)[article]
* [v8 fast properties](https://v8project.blogspot.com/2017/08/fast-properties.html)[article]
* [learning v8](https://github.com/danbev/learning-v8)[github]
* [Intro to Chrome’s V8 from an exploit development angle](https://sensepost.com/blog/2020/intro-to-chromes-v8-from-an-exploit-development-angle/)[article]
* [Introduction to TurboFan](https://doar-e.github.io/blog/2019/01/28/introduction-to-turbofan/)[article]
* [V8 / Chrome Architecture Reading List - For Vulnerability Researchers](https://zon8.re/posts/v8-chrome-architecture-reading-list-for-vulnerability-researchers/)

## Writeup and Exploit Tech
* [Mobile Pwn2Own Autumn 2013 - Chrome on Android - Exploit Writeup](https://docs.google.com/document/d/1tHElG04AJR5OR2Ex-m_Jsmc8S5fAbRB3s4RmTG_PFnw/edit)[article]
* [Exploiting a V8 OOB write](https://halbecaf.com/2017/05/24/exploiting-a-v8-oob-write/)[article]
* [Pointer Compression in V8](https://blog.infosectcbr.com.au/2020/02/pointer-compression-in-v8.html)[article]
* [Exploiting the Math.expm1 typing bug in V8](https://abiondo.me/2019/01/02/exploiting-math-expm1-v8/)[article]
* [Exploiting an Accidentally Discovered V8 RCE](https://zon8.re/posts/exploiting-an-accidentally-discovered-v8-rce/)
* [Escaping the Chrome Sandbox via an IndexedDB Race Condition](https://labs.bluefrostsecurity.de/blog/2019/08/08/escaping-the-chrome-sandbox-via-an-indexeddb-race-condition/)[article]
* [Exploiting CVE-2020-0041 - Part 1: Escaping the Chrome Sandbox](https://labs.bluefrostsecurity.de/blog/2020/03/31/cve-2020-0041-part-1-sandbox-escape/)[article]
* [Cleanly Escaping the Chrome Sandbox](https://theori.io/research/escaping-chrome-sandbox)[article]
* [Escaping the Chrome Sandbox with RIDL](https://googleprojectzero.blogspot.com/2020/02/escaping-chrome-sandbox-with-ridl.html)[article]
* [You Won't Believe what this One Line Change Did to the Chrome Sandbox](https://googleprojectzero.blogspot.com/2020/04/you-wont-believe-what-this-one-line.html)[article]

# IE
## Basic
* [Microsoft Edge MemGC Internals](https://hitcon.org/2015/CMT/download/day2-h-r1.pdf)[slides]
* [The ECMA and the Chakra]( http://conference.hitb.org/hitbsecconf2017ams/materials/CLOSING%20KEYNOTE%20-%20Natalie%20Silvanovich%20-%20The%20ECMA%20and%20The%20Chakra.pdf)[slides]

## Writeup and Exploit Tech
* [2012 - Memory Corruption Exploitation In Internet Explorer](https://www.syscan360.org/slides/2012_ZH_MemoryCorruptionExploitationInInternetExplorer_MotiJoseph.pdf)[slides]
* [2013 - IE 0day Analysis And Exploit](http://vdisk.weibo.com/s/dC_SSJ6Fvb71i)[slides]
* [2014 - Write Once, Pwn Anywhere](https://www.blackhat.com/docs/us-14/materials/us-14-Yu-Write-Once-Pwn-Anywhere.pdf)[slides]
* [2014 - The Art of Leaks: The Return of Heap Feng Shui](https://cansecwest.com/slides/2014/The%20Art%20of%20Leaks%20-%20read%20version%20-%20Yoyo.pdf)[slides]
* [2014 - IE 11 0day & Windows 8.1 Exploit](https://github.com/exp-sky/HitCon-2014-IE-11-0day-Windows-8.1-Exploit/blob/master/IE%2011%200day%20%26%20Windows%208.1%20Exploit.pdf)[slides]
* [2014 - IE11 Sandbox Escapes Presentation](https://www.blackhat.com/docs/us-14/materials/us-14-Forshaw-Digging-For_IE11-Sandbox-Escapes.pdf)[slides]
* [2015 - Spartan 0day & Exploit](https://github.com/exp-sky/HitCon-2015-spartan-0day-exploit)[slides]
* [2015 - 浏览器漏洞攻防对抗的艺术 Art of browser Vulnerability attack and defense (Chinese)](http://www.secseeds.com/holes/yishufenxi.pdf)[slides]
* [2016 - Look Mom, I don't use Shellcode](https://www.syscan360.org/slides/2016_SH_Moritz_Jodeit_Look_Mom_I_Dont_Use_Shellcode.pdf)[slides]
* [2016 - Windows 10 x64 edge 0day and exploit](https://github.com/exp-sky/HitCon-2016-Windows-10-x64-edge-0day-and-exploit/blob/master/Windows%2010%20x64%20edge%200day%20and%20exploit.pdf)[slides]
* [2017 - 1-Day Browser & Kernel Exploitation](http://powerofcommunity.net/poc2017/andrew.pdf)[slides]
* [2017 - The Secret of ChakraCore: 10 Ways to Go Beyond the Edge](http://conference.hitb.org/hitbsecconf2017ams/materials/D1T2%20-%20Linan%20Hao%20and%20Long%20Liu%20-%20The%20Secret%20of%20ChakraCore.pdf)[slides]
* [2017 - From Out of Memory to Remote Code Executio](https://speakerd.s3.amazonaws.com/presentations/c0a3e7bc0dca407cbafb465828ff204a/From_Out_of_Memory_to_Remote_Code_Execution_Yuki_Chen_PacSec2017_final.pdf)[slides]
* [2018 - Edge Inline Segment Use After Free (Chinese)](https://blogs.projectmoon.pw/2018/09/15/Edge-Inline-Segment-Use-After-Free/)

## Mitigation
* [2017 - CROSS THE WALL-BYPASS ALL MODERN MITIGATIONS OF MICROSOFT EDGE](https://www.blackhat.com/docs/asia-17/materials/asia-17-Li-Cross-The-Wall-Bypass-All-Modern-Mitigations-Of-Microsoft-Edge.pdf)[slides]
* [Browser security mitigations against memory corruption vulnerabilities](https://docs.google.com/document/d/19dspgrz35VoJwdWOboENZvccTSGudjQ_p8J4OPsYztM/edit)[references]
* [Browsers and app specific security mitigation (Russian) part 1](https://habr.com/company/dsec/blog/310676/)[article]
* [Browsers and app specific security mitigation (Russian) part 2](https://habr.com/company/dsec/blog/311616/)[article]
* [Browsers and app specific security mitigation (Russian) part 3](https://habr.com/company/dsec/blog/319234/)[article]

# JSC
## Basic
* [JSC loves ES6](https://webkit.org/blog/7536/jsc-loves-es6/)[article] // multiple articles can be found within
* [JavaScriptCore, the WebKit JS implementation](http://wingolog.org/archives/2011/10/28/javascriptcore-the-webkit-js-implementation)[article]
* [saelo's Pwn2Own 2018 Safari + macOS](https://github.com/saelo/pwn2own2018)[exploit]
* [WebKit & JSC Architecture Reading List - For Vulnerability Researchers](https://zon8.re/posts/jsc-architecture-reading-list-for-vulnerability-researchers/)

## Writeup and Exploit Tech
* [Attacking WebKit Applications by exploiting memory corruption bugs](https://docplayer.net/19835745-Attacking-webkit-applications-by-exploiting-memory-corruption-bugs-liang-chen-keenteam-chenliang0817.html)[slides]
* [Vulnerability Discovery Against Apple Safari](https://blog.ret2.io/2018/06/13/pwn2own-2018-vulnerability-discovery/)[article]
* [A Methodical Approach to Browser Exploitation - six part blog](https://blog.ret2.io/2018/06/05/pwn2own-2018-exploit-development/)[article]
* [Adventures on Hunting for Safari Sandbox Escapes](https://www.youtube.com/watch?v=fTNzylTMYks)[video]


# Firefox
## Basic
* [SpiderMonkey Internals](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/SpiderMonkey/Internals)[article]
* [JavaScript:New to SpiderMonkey](https://wiki.mozilla.org/JavaScript:New_to_SpiderMonkey)[article]

## Writeup and Exploit Tech
* [CVE-2018-5129: Out-of-bounds write with malformed IPC messages](https://infinite.loopsec.com.au/cve-2018-5129-how-i-found-my-first-cve)[article]
* [Firefox Spidermonkey JS Engine Exploitation](https://blog.infosectcbr.com.au/2020/01/firefox-spidermonkey-js-engine.html)[article]

# Misc
## Browser Basic
* [Sea of Nodes](https://darksi.de/d.sea-of-nodes/)[articles] // multiple articles can be found within
* [LiveOverflow Browser Exploit Series](https://liveoverflow.com/tag/browser-exploitation/)[articles]
* [Demystifying Browsers](https://textslashplain.com/2020/02/09/demystifying-browsers/)[articles]

## Fuzzing
* [The Power-Of Pair](https://www.blackhat.com/docs/eu-14/materials/eu-14-Lu-The-Power-Of-Pair-One-Template-That-Reveals-100-plus-UAF-IE-Vulnerabilities.pdf)[slides]
* [Browser Fuzzing](https://www.syscan360.org/slides/2014_ZH_BrowserFuzzing_RosarioValotta.pdf)[slides]
* [Taking Browsers Fuzzing To The Next (DOM) Level](https://docs.google.com/viewer?a=v&pid=sites&srcid=ZGVmYXVsdGRvbWFpbnx0ZW50YWNvbG92aW9sYXxneDo1MTgyOTgyYmUyYWY3MWQy)[slides]
* [DOM fuzzer - domato](https://github.com/google/domato)[github]
* [browser fuzzing framework - morph](https://github.com/walkerfuz/morph)[github]
* [browser fuzzing and crash management framework - grinder](https://github.com/stephenfewer/grinder)[github]
* [Browser Fuzzing with a Twist](http://2015.zeronights.org/assets/files/16-Brown.pdf)[slides]
* [Browser fuzzing - peach](https://wiki.mozilla.org/Security/Fuzzing/Peach)[wiki]
* [从零开始学Fuzzing系列：浏览器挖掘框架Morph诞生记 Learn Fuzzing from Very Start: the Birth of Browser Vulnerability Detection Framework Morph(Chinese)](http://www.freebuf.com/sectool/89001.html)[article]
* [BROWSER FUZZING IN 2014:David vs Goliath](https://www.syscan360.org/slides/2014_EN_BrowserFuzzing_RosarioValotta.pdf)[slides]
* [A Review of Fuzzing Tools and Methods](https://dl.packetstormsecurity.net/papers/general/a-review-of-fuzzing-tools-and-methods.pdf)[article]

## Writeup and Exploit Tech
* [it-sec catalog browser exploitation chapter](https://www.it-sec-catalog.info/browser_exploitation.html)[articles]
* [2014 - Smashing The Browser: From Vulnerability Discovery To Exploit](https://hitcon.org/2014/downloads/P1_06_Chen%20Zhang%20-%20Smashing%20The%20Browser%20-%20From%20Vulnerability%20Discovery%20To%20Exploit.pdf)[slides]
* [smash the browser](https://github.com/demi6od/Smashing_The_Browser)[github]

## Collections
* [uxss-db](https://github.com/Metnew/uxss-db)
* [js-vuln-db](https://github.com/tunz/js-vuln-db)

# Thanks
* 0x9a82
* [swing](https://github.com/WinMin)
* [Metnew](https://github.com/Metnew)
* [AlirezaChegini](https://github.com/AlirezaChegini)
* [RobertLarsen](https://github.com/RobertLarsen)
